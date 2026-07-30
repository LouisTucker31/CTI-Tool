/**
 * file-extraction.js — turns an uploaded file (.txt, .pdf, .docx, .xlsx)
 * into plain text, ready to hand straight to parseReport().
 *
 * PDF.js ships proper ES modules, so it's imported directly from its CDN
 * right here (dynamically, only when a PDF is actually chosen — no point
 * fetching a few hundred KB of library on every page load if someone's
 * only ever importing .txt files). Mammoth and SheetJS only ship classic
 * browser builds, so they're loaded via <script> tags in index.html
 * instead, same pattern as Leaflet/Chart.js, and used here as the
 * `mammoth` and `XLSX` globals.
 *
 * PDF text reconstruction is the one subtle part: PDF.js's getTextContent()
 * returns individual positioned text fragments, not lines — naively
 * joining them all with spaces collapses every line on a page into one
 * continuous run of text, which breaks the parser (it reads the import
 * block line by line). Each fragment carries its own `hasEOL` flag marking
 * whether a real line break followed it in the original document; using
 * that reconstructs the original line structure correctly. This was
 * verified against a real generated PDF (not just read about) before
 * writing this — the naive space-joined version silently produced text
 * the parser couldn't read at all.
 *
 * XLSX has a similar trap: SheetJS's own sheet_to_txt utility actually
 * outputs UTF-16-formatted text (with a null byte woven between every
 * character) — meant for saving as a real .txt file, not for use as a
 * plain JS string. Reading cells directly via sheet_to_json instead and
 * joining them ourselves avoids that entirely. Also verified against a
 * real generated XLSX file before writing this.
 */

const PDFJS_VERSION = '5.4.149';
const PDFJS_URL = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.min.mjs`;
const PDFJS_WORKER_URL = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.worker.min.mjs`;

let pdfjsLibPromise = null;

function loadPdfjsLib() {
  if (!pdfjsLibPromise) {
    pdfjsLibPromise = import(/* webpackIgnore: true */ PDFJS_URL).then((lib) => {
      lib.GlobalWorkerOptions.workerSrc = PDFJS_WORKER_URL;
      return lib;
    });
  }
  return pdfjsLibPromise;
}

async function extractTextFromPdf(file) {
  const pdfjsLib = await loadPdfjsLib();
  const buffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: new Uint8Array(buffer) }).promise;

  const pageTexts = [];
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const textContent = await page.getTextContent();
    let pageText = '';
    for (const item of textContent.items) {
      pageText += item.str;
      if (item.hasEOL) pageText += '\n';
    }
    pageTexts.push(pageText);
  }

  const fullText = pageTexts.join('\n');
  if (fullText.trim().length < 50) {
    throw new Error(
      "No selectable text found in this PDF — it may be a scanned image rather than a text-based document, which isn't supported yet."
    );
  }
  return fullText;
}

async function extractTextFromDocx(file) {
  const arrayBuffer = await file.arrayBuffer();
  const result = await mammoth.extractRawText({ arrayBuffer });
  return result.value;
}

async function extractTextFromXlsx(file) {
  const buffer = await file.arrayBuffer();
  const workbook = XLSX.read(buffer, { type: 'array' });

  const sheetTexts = workbook.SheetNames.map((name) => {
    const sheet = workbook.Sheets[name];
    const rows = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    return rows.map((row) => (row || []).join(' ')).join('\n');
  });

  return sheetTexts.join('\n');
}

export async function extractTextFromFile(file) {
  const name = (file.name || '').toLowerCase();
  if (name.endsWith('.pdf')) return extractTextFromPdf(file);
  if (name.endsWith('.docx')) return extractTextFromDocx(file);
  if (name.endsWith('.xlsx') || name.endsWith('.xls')) return extractTextFromXlsx(file);
  if (name.endsWith('.txt')) return file.text();
  throw new Error(`Unsupported file type for "${file.name}". Please upload a .txt, .pdf, .docx, or .xlsx file.`);
}
