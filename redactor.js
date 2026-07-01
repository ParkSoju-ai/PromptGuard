/**
 * redactor.js
 * ----------------------------------------------------------------------------
 * Given the original text and the list of findings (each with a start/end
 * index into that text), produces a redacted version where every matched
 * value is replaced with its category placeholder, e.g. [EMAIL], [OPENAI_API_KEY].
 *
 * Replacements are applied from the END of the string backwards so that
 * earlier indices remain valid as we go (otherwise each replacement would
 * shift the offsets of everything after it).
 * ----------------------------------------------------------------------------
 */

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * @param {string} text - the original, unredacted text
 * @param {Array} findings - array of { start, end, placeholder, severity } objects
 * @returns {string} redacted text
 */
function redactText(text, findings) {
  if (!findings || findings.length === 0) return text;

  // Resolve overlaps by preference: higher severity wins, then longer match,
  // then earliest start. This ensures e.g. a full MongoDB connection string
  // (critical) is redacted as one block rather than being partially
  // overwritten by a lower-priority match nested inside it (e.g. an email).
  const byPriority = [...findings].sort((a, b) => {
    const rankA = SEVERITY_RANK[a.severity] || 0;
    const rankB = SEVERITY_RANK[b.severity] || 0;
    if (rankB !== rankA) return rankB - rankA;
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenB !== lenA) return lenB - lenA;
    return a.start - b.start;
  });

  const accepted = [];
  for (const finding of byPriority) {
    const overlapsAccepted = accepted.some(
      (a) => finding.start < a.end && finding.end > a.start
    );
    if (!overlapsAccepted) accepted.push(finding);
  }

  // Apply replacements from the end of the string backwards so earlier
  // offsets stay valid as each replacement is made.
  accepted.sort((a, b) => b.start - a.start);

  let result = text;
  for (const finding of accepted) {
    const placeholder = finding.placeholder || '[REDACTED]';
    result = result.slice(0, finding.start) + placeholder + result.slice(finding.end);
  }

  return result;
}

/**
 * Copies text to the clipboard using the Clipboard API, with an
 * execCommand fallback for older / restricted contexts. Returns a Promise.
 */
async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // fall through to legacy method
    }
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch (err) {
    return false;
  }
}

window.PromptGuardRedactor = {
  redactText,
  copyToClipboard
};
