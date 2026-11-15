"""Bounded local document extraction, chunk storage and semantic/lexical retrieval."""
import asyncio
import hashlib
import heapq
import io
import math
import re
import zipfile
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

MAX_FILE = 8 * 1024 * 1024
MAX_TEXT = 800000


class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style'}: self.skip += 1
    def handle_endtag(self, tag):
        if tag in {'script', 'style'}: self.skip = max(0, self.skip - 1)
        self.parts.append('\n')
    def handle_data(self, data):
        if not self.skip: self.parts.append(data)


def extract(name, data):
    if len(data) > MAX_FILE:
        raise ValueError('Knowledge import exceeds 8 MiB')
    suffix = Path(name).suffix.lower()
    if suffix in {'.txt', '.md', '.markdown', '.json', '.csv', '.log'}:
        text = data.decode('utf-8-sig', errors='replace')
    elif suffix in {'.html', '.htm'}:
        parser = _HTML(); parser.feed(data.decode('utf-8', errors='replace')); text = ' '.join(parser.parts)
    elif suffix == '.docx':
        from defusedxml import ElementTree
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > 2000 or sum(i.file_size for i in infos) > 32 * 1024 * 1024:
                raise ValueError('DOCX decompression limits exceeded')
            xml = archive.read('word/document.xml')
        root = ElementTree.fromstring(xml)
        namespace = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
        text = '\n'.join(''.join(p.itertext()) for p in root.findall('.//' + namespace + 'p'))
    elif suffix == '.pdf':
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ValueError('Encrypted PDFs are unsupported')
        if len(reader.pages) > 300:
            raise ValueError('PDF exceeds 300 pages')
        parts = []; count = 0
        for page in reader.pages:
            part = page.extract_text() or ''; count += len(part)
            if count > MAX_TEXT:
                raise ValueError('Extracted text exceeds 800,000 characters')
            parts.append(part)
        text = '\n'.join(parts)
    else:
        raise ValueError('Supported knowledge files: PDF, DOCX, TXT, Markdown, HTML, JSON and CSV')
    if len(text) > MAX_TEXT or not text.strip():
        raise ValueError('Document has no extractable text or exceeds 800,000 characters; OCR is not included')
    return text.replace('\x00', '')


def cosine(a, b):
    if len(a) != len(b): return 0.0
    norm = math.sqrt(sum(x * x for x in a) * sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / norm if norm else 0.0


class KnowledgeService:
    def __init__(self, state, provider=None):
        self.state = state; self.db = state.database
        if provider is None:
            from .intelligence import InferenceProvider
            provider = InferenceProvider(state.settings)
        self.provider = provider

    def list(self, limit=200):
        return self.db.listing('document', limit=limit)

    async def import_file(self, value):
        import asyncio
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError('Select a regular document file no larger than 8 MiB')
        data = path.read_bytes()
        try:
            text = await asyncio.to_thread(extract, path.name, data)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError('Could not parse the document; check its format and extraction limits') from exc
        parts = [text[i:i + 1600] for i in range(0, len(text), 1400)]
        vectors, model, warning = await self._embed(parts)
        document = self.db.create('document', {'name': path.name, 'sha256': hashlib.sha256(data).hexdigest(),
            'chunk_count': len(parts), 'embedding_model': model, 'semantic': bool(vectors), 'warning': warning,
            'original_bytes_retained': False})
        created = []
        try:
            for index, part in enumerate(parts):
                row = self.db.create('knowledge_chunk', {'document_id': document['id'], 'name': path.name,
                    'index': index, 'text': part, 'vector': vectors[index] if vectors else [], 'embedding_model': model}, document['id'])
                created.append(row['id'])
        except BaseException:
            for rid in created: self.db.remove('knowledge_chunk', rid)
            self.db.remove('document', document['id'])
            raise
        self.db.audit('knowledge.imported', {'id': document['id'], 'chunks': len(parts), 'semantic': bool(vectors)})
        return document

    async def _embed(self, parts):
        model = self.state.settings.embedding_model
        if not model:
            return [], '', 'Semantic retrieval disabled: select an embedding model. Lexical search is available.'
        vectors = []
        try:
            for i in range(0, len(parts), 16):
                vectors.extend(await self.provider.embed(model, parts[i:i + 16]))
            return vectors, model, ''
        except asyncio.CancelledError:
            raise
        except Exception:
            return [], '', 'Local embeddings failed. Document retained with lexical retrieval; configure Ollama then reindex.'

    async def search(self, query, limit=5):
        if not query.strip() or len(query) > 4000 or not 1 <= limit <= 20:
            raise ValueError('Search query must contain 1–4000 characters; result limit is 1–20')
        model = self.state.settings.embedding_model; vector = None; method = 'lexical'
        compatible_library = False
        document_offset = 0
        if model:
            while True:
                documents = self.db.listing('document', limit=200, offset=document_offset)
                if not documents: break
                document_offset += len(documents)
                if any(document.get('embedding_model') == model and document.get('semantic') for document in documents):
                    compatible_library = True; break
        # Avoid loading an embedding model for an empty or wholly lexical library.
        if model and compatible_library:
            try:
                vector = (await self.provider.embed(model, [query]))[0]
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        terms = Counter(re.findall(r'\w+', query.casefold()))
        heap = []; offset = 0; semantic_used = False; sequence = 0
        while True:
            rows = self.db.listing('knowledge_chunk', limit=200, offset=offset)
            if not rows: break
            offset += len(rows)
            for chunk in rows:
                words = Counter(re.findall(r'\w+', chunk['text'].casefold()))
                lexical = sum(min(n, words[term]) for term, n in terms.items()) / max(1, sum(terms.values()))
                compatible = vector is not None and chunk.get('embedding_model') == model and bool(chunk.get('vector')) and len(vector) == len(chunk['vector'])
                semantic = cosine(vector, chunk['vector']) if compatible else 0
                semantic_used |= compatible
                score = semantic + lexical * .15 if compatible else lexical * (.15 if vector is not None else 1)
                if score <= 0: continue
                result = {'chunk_id': chunk['id'], 'document_id': chunk['document_id'], 'name': chunk['name'],
                          'index': chunk['index'], 'text': chunk['text'], 'score': round(score, 4),
                          'method': 'semantic+lexical' if compatible else 'lexical'}
                sequence += 1; item = (score, sequence, result)
                if len(heap) < limit: heapq.heappush(heap, item)
                elif score > heap[0][0]: heapq.heapreplace(heap, item)
        if semantic_used: method = 'semantic+lexical'
        return {'method': method, 'results': [r for _, _, r in sorted(heap, key=lambda item: item[0], reverse=True)]}

    async def reindex(self, rid):
        document = self.db.get('document', rid)
        if not self.state.settings.embedding_model:
            raise ValueError('Configure an embedding model before reindexing')
        rows = list(reversed(self.db.listing('knowledge_chunk', parent=rid, limit=1000)))
        rows.sort(key=lambda item: item['index'])
        vectors, model, warning = await self._embed([row['text'] for row in rows])
        if warning:
            raise ValueError(warning)
        for row, vector in zip(rows, vectors):
            self.db.update('knowledge_chunk', row['id'], {'vector': vector, 'embedding_model': model})
        result = self.db.update('document', rid, {'embedding_model': model, 'semantic': True, 'warning': ''})
        self.db.audit('knowledge.reindexed', {'id': rid, 'model': model})
        return result

    def remove(self, rid):
        self.db.get('document', rid)
        while True:
            chunks = self.db.listing('knowledge_chunk', parent=rid, limit=200)
            if not chunks: break
            for chunk in chunks: self.db.remove('knowledge_chunk', chunk['id'])
        self.db.remove('document', rid)
        self.db.audit('knowledge.removed', {'id': rid})
