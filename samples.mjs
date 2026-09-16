// Sample repositories offered on the landing page.
//
// Chosen by scanning each one and keeping a spread of outcomes, not by
// popularity: something that finds a removal, something that finds only
// deprecations, something genuinely clean, and something whose scan cannot be
// complete. A visitor who clicks three of these should see three different
// shapes of answer.
//
// Deliberately no claim about what each one reports. Those repositories change,
// this file does not, and a label promising "22 findings" would be a lie within
// a month. Every one is under about a hundred Python files, so no sample takes
// long enough to look broken.

export const SAMPLES = [
  "https://github.com/benjaminp/six",
  "https://github.com/certifi/python-certifi",
  "https://github.com/kennethreitz/records",
  "https://github.com/jazzband/tablib",
  "https://github.com/psf/requests",
  "https://github.com/python-attrs/attrs",
  "https://github.com/urllib3/urllib3",
  "https://github.com/pallets/click",
];

/** A random handful, without repeats. */
export function pickSamples(count = 3, pool = SAMPLES, random = Math.random) {
  const remaining = [...pool];
  const chosen = [];
  while (chosen.length < Math.min(count, pool.length)) {
    chosen.push(...remaining.splice(Math.floor(random() * remaining.length), 1));
  }
  return chosen;
}
