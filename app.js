/**
 * app.js
 * ----------------------------------------------------------------------------
 * Orchestrates the PromptGuard UI. Depends on the globals exposed by
 * patterns.js, risk.js and redactor.js (loaded before this file).
 *
 * Responsibilities:
 *  - Run a scan over the textarea contents using PromptGuardPatterns
 *  - Render the privacy score, summary tiles, and per-finding cards
 *  - Handle redaction, clipboard copy, and JSON/TXT report downloads
 *  - Handle drag & drop / file picker ingestion of .txt/.md/.log/.json
 *  - Handle dark/light mode toggle (persisted to localStorage only —
 *    never sent anywhere)
 *
 * Nothing in this file makes a network request. Every operation reads from
 * or writes to the DOM, localStorage, or in-memory state only.
 * ----------------------------------------------------------------------------
 */

(function () {
  'use strict';

  const { PG_PATTERNS, PG_INJECTION_PHRASES, PG_JAILBREAK_PHRASES, findPhraseMatches } = window.PromptGuardPatterns;
  const { computeRiskScore, estimateTokenCount, countWords } = window.PromptGuardRisk;
  const { redactText, copyToClipboard } = window.PromptGuardRedactor;

  // ---------------------------------------------------------------- DOM refs
  const el = (id) => document.getElementById(id);

  const promptInput = el('promptInput');
  const dropZone = el('dropZone');
  const fileInput = el('fileInput');

  const charCount = el('charCount');
  const wordCount = el('wordCount');
  const tokenCount = el('tokenCount');
  const lineCount = el('lineCount');

  const scanBtn = el('scanBtn');
  const redactBtn = el('redactBtn');
  const loadFileBtn = el('loadFileBtn');
  const clearBtn = el('clearBtn');

  const redactedSection = el('redactedSection');
  const redactedOutput = el('redactedOutput');
  const copyRedactedBtn = el('copyRedactedBtn');

  const emptyState = el('emptyState');
  const resultsContent = el('resultsContent');

  const scoreValue = el('scoreValue');
  const scoreLabel = el('scoreLabel');
  const scoreRingFg = el('scoreRingFg');

  const findingsCountValue = el('findingsCountValue');
  const categoriesCountValue = el('categoriesCountValue');
  const criticalCountValue = el('criticalCountValue');
  const highCountValue = el('highCountValue');
  const findingsHint = el('findingsHint');
  const findingsList = el('findingsList');

  const downloadJsonBtn = el('downloadJsonBtn');
  const downloadTxtBtn = el('downloadTxtBtn');
  const darkModeToggle = el('darkModeToggle');
  const darkModeIcon = el('darkModeIcon');

  // ---------------------------------------------------------------- state
  let lastFindings = [];
  let lastScoreResult = null;
  let lastRedactedText = '';

  const SCORE_RING_CIRCUMFERENCE = 2 * Math.PI * 52; // matches r=52 in the SVG

  // ---------------------------------------------------------------- helpers

  /** Maps a finding's severity to one of three card colors (green/yellow/red). */
  function severityToCardColor(severity) {
    if (severity === 'critical' || severity === 'high') return 'red';
    if (severity === 'medium') return 'yellow';
    return 'green';
  }

  /** Returns the 1-indexed line number for a character offset in `text`. */
  function getLineNumber(text, index) {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i++) {
      if (text[i] === '\n') line++;
    }
    return line;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function truncate(str, max) {
    if (str.length <= max) return str;
    return str.slice(0, max) + '… (' + (str.length - max) + ' more chars)';
  }

  // ---------------------------------------------------------------- scanning

  /** Runs every pattern + phrase list against `text` and returns sorted findings. */
  function scanText(text) {
    const findings = [];

    for (const pattern of PG_PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      // Hidden/zero-width characters are summarized as ONE finding instead of
      // spamming the list with a card per invisible character.
      if (pattern.id === 'zero_width_chars' || pattern.id === 'hidden_control_chars') {
        const positions = [];
        let m;
        while ((m = regex.exec(text)) !== null) {
          positions.push(m.index);
          if (m.index === regex.lastIndex) regex.lastIndex++;
        }
        if (positions.length > 0) {
          const start = positions[0];
          const end = positions[positions.length - 1] + 1;
          findings.push({
            category: pattern.category,
            severity: pattern.severity,
            match: positions.length + ' hidden character(s) detected',
            start,
            end,
            line: getLineNumber(text, start),
            recommendation: pattern.recommendation,
            placeholder: pattern.placeholder
          });
        }
        continue;
      }

      let match;
      while ((match = regex.exec(text)) !== null) {
        const matchedText = match[0];
        if (pattern.validate && !pattern.validate(matchedText)) {
          if (match.index === regex.lastIndex) regex.lastIndex++;
          continue;
        }
        findings.push({
          category: pattern.category,
          severity: pattern.severity,
          match: matchedText,
          start: match.index,
          end: match.index + matchedText.length,
          line: getLineNumber(text, match.index),
          recommendation: pattern.recommendation,
          placeholder: pattern.placeholder
        });
        if (match.index === regex.lastIndex) regex.lastIndex++;
      }
    }

    // Phrase-based detectors
    for (const m of findPhraseMatches(text, PG_INJECTION_PHRASES)) {
      findings.push({
        category: 'Prompt Injection Phrase',
        severity: 'high',
        match: text.substr(m.index, m.length),
        start: m.index,
        end: m.index + m.length,
        line: getLineNumber(text, m.index),
        recommendation: 'This phrasing resembles a prompt-injection attempt. Review the surrounding context before sending.',
        placeholder: '[PROMPT_INJECTION]'
      });
    }
    for (const m of findPhraseMatches(text, PG_JAILBREAK_PHRASES)) {
      findings.push({
        category: 'Jailbreak Phrase',
        severity: 'critical',
        match: text.substr(m.index, m.length),
        start: m.index,
        end: m.index + m.length,
        line: getLineNumber(text, m.index),
        recommendation: 'This phrasing resembles a known jailbreak technique. Review before sending to an AI model.',
        placeholder: '[JAILBREAK_PHRASE]'
      });
    }

    findings.sort((a, b) => a.start - b.start);
    return findings;
  }

  // ---------------------------------------------------------------- rendering

  function updateStats() {
    const text = promptInput.value;
    charCount.textContent = text.length.toLocaleString();
    wordCount.textContent = countWords(text).toLocaleString();
    tokenCount.textContent = estimateTokenCount(text).toLocaleString();
    lineCount.textContent = (text === '' ? 0 : text.split('\n').length).toLocaleString();
  }

  function severityRingColor(color) {
    switch (color) {
      case 'green': return getComputedStyle(document.documentElement).getPropertyValue('--severity-green').trim();
      case 'yellow-green': return getComputedStyle(document.documentElement).getPropertyValue('--severity-green').trim();
      case 'yellow': return getComputedStyle(document.documentElement).getPropertyValue('--severity-yellow').trim();
      case 'orange': return getComputedStyle(document.documentElement).getPropertyValue('--severity-yellow').trim();
      case 'red': return getComputedStyle(document.documentElement).getPropertyValue('--severity-red').trim();
      default: return getComputedStyle(document.documentElement).getPropertyValue('--severity-green').trim();
    }
  }

  function renderScore(scoreResult) {
    scoreValue.textContent = scoreResult.score;
    scoreLabel.textContent = scoreResult.label;
    scoreLabel.style.color = severityRingColor(scoreResult.color);

    const offset = SCORE_RING_CIRCUMFERENCE * (1 - scoreResult.score / 100);
    scoreRingFg.style.strokeDasharray = String(SCORE_RING_CIRCUMFERENCE);
    scoreRingFg.style.strokeDashoffset = String(offset);
    scoreRingFg.style.stroke = severityRingColor(scoreResult.color);
  }

  function renderSummary(findings) {
    const categories = new Set(findings.map((f) => f.category));
    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;

    findingsCountValue.textContent = findings.length;
    categoriesCountValue.textContent = categories.size;
    criticalCountValue.textContent = criticalCount;
    highCountValue.textContent = highCount;

    findingsHint.textContent = findings.length === 0
      ? 'No sensitive data detected.'
      : findings.length + ' finding(s) across ' + categories.size + ' categor' + (categories.size === 1 ? 'y' : 'ies');
  }

  function renderFindings(findings) {
    findingsList.innerHTML = '';

    if (findings.length === 0) {
      const div = document.createElement('div');
      div.className = 'pg-panel-sub';
      div.style.padding = '10px 2px';
      div.textContent = 'Nothing flagged — this prompt looks clean.';
      findingsList.appendChild(div);
      return;
    }

    for (const finding of findings) {
      const color = severityToCardColor(finding.severity);
      const card = document.createElement('div');
      card.className = 'pg-finding-card sev-' + color;
      card.innerHTML =
        '<div class="pg-finding-top">' +
          '<span class="pg-finding-category">' + escapeHtml(finding.category) + '</span>' +
          '<span class="pg-severity-chip sev-' + color + '">' + escapeHtml(finding.severity) + '</span>' +
        '</div>' +
        '<div class="pg-finding-value">' + escapeHtml(truncate(finding.match, 160)) + '</div>' +
        '<div class="pg-finding-meta">Line ' + finding.line + '</div>' +
        '<div class="pg-finding-reco"><strong>Recommendation:</strong> ' + escapeHtml(finding.recommendation) + '</div>';
      findingsList.appendChild(card);
    }
  }

  function triggerScanBeam() {
    dropZone.classList.add('pg-scanning');
    setTimeout(() => dropZone.classList.remove('pg-scanning'), 750);
  }

  // ---------------------------------------------------------------- actions

  function runScan() {
    const text = promptInput.value;
    updateStats();
    triggerScanBeam();

    lastFindings = scanText(text);
    lastScoreResult = computeRiskScore(lastFindings);

    emptyState.hidden = true;
    resultsContent.hidden = false;

    renderScore(lastScoreResult);
    renderSummary(lastFindings);
    renderFindings(lastFindings);

    redactBtn.disabled = text.length === 0;

    // Collapse any stale redacted output until the user redacts again.
    redactedSection.hidden = true;
  }

  function runRedact() {
    if (!promptInput.value) return;
    if (lastFindings.length === 0 && lastScoreResult === null) {
      // Allow redact-without-scan as a convenience: scan first, then redact.
      runScan();
    }
    lastRedactedText = redactText(promptInput.value, lastFindings);
    redactedOutput.value = lastRedactedText;
    redactedSection.hidden = false;
    redactedOutput.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function runCopyRedacted() {
    if (!lastRedactedText) return;
    const ok = await copyToClipboard(lastRedactedText);
    const original = copyRedactedBtn.textContent;
    copyRedactedBtn.textContent = ok ? 'Copied ✓' : 'Copy failed';
    setTimeout(() => { copyRedactedBtn.textContent = original; }, 1500);
  }

  function clearAll() {
    promptInput.value = '';
    lastFindings = [];
    lastScoreResult = null;
    lastRedactedText = '';
    updateStats();
    emptyState.hidden = false;
    resultsContent.hidden = true;
    redactedSection.hidden = true;
    redactBtn.disabled = true;
    promptInput.focus();
  }

  function buildReportObject() {
    return {
      tool: 'PromptGuard',
      generatedAt: new Date().toISOString(),
      privacyScore: lastScoreResult ? lastScoreResult.score : null,
      riskLabel: lastScoreResult ? lastScoreResult.label : null,
      stats: {
        characters: promptInput.value.length,
        words: countWords(promptInput.value),
        estimatedTokens: estimateTokenCount(promptInput.value),
        lines: promptInput.value === '' ? 0 : promptInput.value.split('\n').length
      },
      findingsCount: lastFindings.length,
      categories: Array.from(new Set(lastFindings.map((f) => f.category))),
      findings: lastFindings.map((f) => ({
        category: f.category,
        severity: f.severity,
        matchedValue: f.match,
        line: f.line,
        recommendation: f.recommendation
      }))
    };
  }

  function downloadBlob(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function downloadJsonReport() {
    if (!lastScoreResult) runScan();
    const report = buildReportObject();
    downloadBlob(JSON.stringify(report, null, 2), 'promptguard-report.json', 'application/json');
  }

  function downloadTxtReport() {
    if (!lastScoreResult) runScan();
    const report = buildReportObject();
    const lines = [];
    lines.push('PromptGuard Scan Report');
    lines.push('Generated: ' + report.generatedAt);
    lines.push('');
    lines.push('Privacy Score: ' + report.privacyScore + ' / 100 (' + report.riskLabel + ')');
    lines.push('Characters: ' + report.stats.characters + '  Words: ' + report.stats.words +
      '  Est. Tokens: ' + report.stats.estimatedTokens + '  Lines: ' + report.stats.lines);
    lines.push('Findings: ' + report.findingsCount + '  Categories: ' + report.categories.join(', '));
    lines.push('');
    lines.push('--------------------------------------------------------------------');
    if (report.findings.length === 0) {
      lines.push('No sensitive data detected.');
    } else {
      report.findings.forEach((f, i) => {
        lines.push('');
        lines.push('[' + (i + 1) + '] ' + f.category + ' — severity: ' + f.severity.toUpperCase() + ' — line ' + f.line);
        lines.push('    Value: ' + f.matchedValue);
        lines.push('    Recommendation: ' + f.recommendation);
      });
    }
    lines.push('');
    lines.push('--------------------------------------------------------------------');
    lines.push('Generated entirely offline by PromptGuard. No data left this browser.');
    downloadBlob(lines.join('\n'), 'promptguard-report.txt', 'text/plain');
  }

  // ---------------------------------------------------------------- file ingestion

  function handleIncomingFile(file) {
    const allowedExt = ['.txt', '.md', '.log', '.json'];
    const name = file.name.toLowerCase();
    if (!allowedExt.some((ext) => name.endsWith(ext))) {
      alert('Unsupported file type. Please use .txt, .md, .log, or .json files.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      promptInput.value = e.target.result;
      updateStats();
      runScan();
    };
    reader.onerror = () => alert('Could not read that file.');
    reader.readAsText(file);
  }

  // ---------------------------------------------------------------- dark mode

  function applyTheme(theme) {
    if (theme === 'light') {
      document.body.classList.add('pg-light');
      darkModeIcon.textContent = '☀️';
    } else {
      document.body.classList.remove('pg-light');
      darkModeIcon.textContent = '🌙';
    }
    if (lastScoreResult) renderScore(lastScoreResult); // refresh ring color for new theme
  }

  function initTheme() {
    const saved = localStorage.getItem('promptguard-theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'dark'); // default to dark regardless of system, matches brand
    applyTheme(theme);
  }

  function toggleTheme() {
    const isLight = document.body.classList.contains('pg-light');
    const next = isLight ? 'dark' : 'light';
    localStorage.setItem('promptguard-theme', next);
    applyTheme(next);
  }

  // ---------------------------------------------------------------- event wiring

  scanBtn.addEventListener('click', runScan);
  redactBtn.addEventListener('click', runRedact);
  clearBtn.addEventListener('click', clearAll);
  copyRedactedBtn.addEventListener('click', runCopyRedacted);
  downloadJsonBtn.addEventListener('click', downloadJsonReport);
  downloadTxtBtn.addEventListener('click', downloadTxtReport);
  darkModeToggle.addEventListener('click', toggleTheme);
  loadFileBtn.addEventListener('click', () => fileInput.click());

  promptInput.addEventListener('input', () => {
    updateStats();
    redactBtn.disabled = promptInput.value.length === 0;
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleIncomingFile(e.target.files[0]);
    }
    fileInput.value = '';
  });

  ['dragenter', 'dragover'].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('pg-drag-active');
    });
  });
  ['dragleave', 'drop'].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (evt === 'dragleave' && e.target !== dropZone) return;
      dropZone.classList.remove('pg-drag-active');
    });
  });
  dropZone.addEventListener('drop', (e) => {
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) handleIncomingFile(file);
  });

  // Keyboard shortcut: Ctrl/Cmd + Enter triggers scan from the textarea.
  promptInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runScan();
    }
  });

  // ---------------------------------------------------------------- init
  initTheme();
  updateStats();
})();
