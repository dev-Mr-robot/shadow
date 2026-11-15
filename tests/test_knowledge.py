import io
import zipfile
import pytest
from shadow.knowledge import KnowledgeService, extract, MAX_FILE


class Embeddings:
    def __init__(self):self.fail = False
    async def embed(self, model, texts):
        if self.fail:raise RuntimeError('offline')
        return [[1., 0.] for _ in texts]


async def test_lexical_document_import_provenance_search_and_removal(runtime, tmp_path):
    file = tmp_path / 'notes.md'; file.write_text('# SSH assessment\nInspect key algorithms and authentication policy.', encoding='utf-8')
    service = KnowledgeService(runtime, Embeddings()); doc = await service.import_file(file)
    assert len(doc['sha256']) == 64 and not doc['semantic'] and doc['warning']
    result = await service.search('SSH authentication')
    assert result['method'] == 'lexical' and result['results'][0]['document_id'] == doc['id']
    assert result['results'][0]['chunk_id']
    service.remove(doc['id'])
    assert service.list() == [] and runtime.database.listing('knowledge_chunk') == []


async def test_semantic_reindex_then_embedding_failure_falls_back(runtime, tmp_path):
    file = tmp_path / 'notes.txt'; file.write_text('Authentication and authorization evidence', encoding='utf-8')
    provider = Embeddings(); service = KnowledgeService(runtime, provider); doc = await service.import_file(file)
    runtime.settings.embedding_model = 'embed:local'
    assert (await service.reindex(doc['id']))['semantic']
    result = await service.search('access control')
    assert result['method'] == 'semantic+lexical' and result['results']
    provider.fail = True
    result = await service.search('authentication')
    assert result['method'] == 'lexical' and result['results']
    with pytest.raises(ValueError, match='Local embeddings failed'):
        await service.reindex(doc['id'])


async def test_embedding_model_switch_does_not_compare_incompatible_vectors(runtime, tmp_path):
    runtime.settings.embedding_model = 'first'
    file = tmp_path / 'a.txt'; file.write_text('SSH hardening')
    service = KnowledgeService(runtime, Embeddings()); await service.import_file(file)
    runtime.settings.embedding_model = 'second'
    result = await service.search('SSH')
    assert result['method'] == 'lexical' and result['results'][0]['method'] == 'lexical'


def test_html_and_docx_static_extraction_rejects_active_xml():
    assert 'alert' not in extract('a.html', b'<style>x</style><script>alert(1)</script><p>evidence</p>')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as file:
        file.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>evidence</w:t></w:r></w:p></w:document>')
    assert extract('a.docx', archive.getvalue()) == 'evidence'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as file:
        file.writestr('word/document.xml', '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    with pytest.raises(Exception):extract('a.docx', archive.getvalue())


def test_pdf_extracts_fixture_text_and_enforces_limits():
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
    writer = PdfWriter(); page = writer.add_blank_page(200, 200)
    font = DictionaryObject({NameObject('/Type'): NameObject('/Font'), NameObject('/Subtype'): NameObject('/Type1'), NameObject('/BaseFont'): NameObject('/Helvetica')})
    page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): writer._add_object(font)})})
    stream = DecodedStreamObject(); stream.set_data(b'BT /F1 12 Tf 20 100 Td (Security evidence) Tj ET')
    page[NameObject('/Contents')] = writer._add_object(stream)
    output = io.BytesIO(); writer.write(output)
    assert 'Security evidence' in extract('evidence.pdf', output.getvalue())
    with pytest.raises(ValueError):extract('a.exe', b'not executed')
    with pytest.raises(ValueError):extract('a.txt', b'x' * (MAX_FILE + 1))
    with pytest.raises(ValueError):extract('empty.txt', b'')


async def test_large_chunk_library_search_pages_without_materializing_every_record(runtime):
    document = runtime.database.create('document', {'name': 'large', 'chunk_count': 240})
    for index in range(240):
        runtime.database.create('knowledge_chunk', {'document_id': document['id'], 'name': 'large', 'index': index,
            'text': 'needle evidence' if index == 239 else 'unrelated', 'vector': [], 'embedding_model': ''}, document['id'])
    result = await KnowledgeService(runtime, Embeddings()).search('needle')
    assert result['results'][0]['index'] == 239
