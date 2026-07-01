/**
 * risk.js
 * ----------------------------------------------------------------------------
 * Turns a list of findings (produced by app.js using patterns.js) into a
 * single 0–100 Privacy Score, plus a human-readable label and color.
 *
 * Scoring approach
 * -----------------------------------------------------------------------
 * - Start at 100 points.
 * - Each finding subtracts points based on its severity.
 * - To stop one giant paste (e.g. 40 emails) from instantly flooring the
 *   score, repeated findings of the *same category* beyond the first 3
 *   are weighted at half value.
 * - Score is clamped to the 0–100 range.
 * ----------------------------------------------------------------------------
 */

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 12,
  medium: 6,
  low: 3
};

const SCORE_BANDS = [
  { min: 90, label: 'Safe', color: 'green' },
  { min: 75, label: 'Minor Issues', color: 'yellow-green' },
  { min: 50, label: 'Moderate Risk', color: 'yellow' },
  { min: 25, label: 'High Risk', color: 'orange' },
  { min: 0, label: 'Critical', color: 'red' }
];

function getScoreBand(score) {
  for (const band of SCORE_BANDS) {
    if (score >= band.min) return band;
  }
  return SCORE_BANDS[SCORE_BANDS.length - 1];
}

/**
 * @param {Array} findings - array of finding objects, each with a `severity`
 *   and `category` field (see app.js for the full shape).
 * @returns {{score:number, label:string, color:string, breakdown:Object}}
 */
function computeRiskScore(findings) {
  if (!findings || findings.length === 0) {
    return { score: 100, label: 'Safe', color: 'green', breakdown: {} };
  }

  // Count occurrences per category so we can apply diminishing penalties.
  const countByCategory = {};
  let totalPenalty = 0;

  for (const finding of findings) {
    const key = finding.category;
    countByCategory[key] = (countByCategory[key] || 0) + 1;
    const occurrence = countByCategory[key];
    const baseWeight = SEVERITY_WEIGHTS[finding.severity] || SEVERITY_WEIGHTS.low;

    // First 3 occurrences of a category count fully, after that at half weight.
    const weight = occurrence <= 3 ? baseWeight : baseWeight * 0.5;
    totalPenalty += weight;
  }

  let score = Math.round(100 - totalPenalty);
  score = Math.max(0, Math.min(100, score));

  const band = getScoreBand(score);

  return {
    score,
    label: band.label,
    color: band.color,
    breakdown: countByCategory
  };
}

/** Rough heuristic: ~4 characters per token, which is a common approximation for English text. */
function estimateTokenCount(text) {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}

function countWords(text) {
  if (!text) return 0;
  const trimmed = text.trim();
  if (trimmed === '') return 0;
  return trimmed.split(/\s+/).length;
}

window.PromptGuardRisk = {
  computeRiskScore,
  estimateTokenCount,
  countWords,
  SEVERITY_WEIGHTS,
  SCORE_BANDS
};
