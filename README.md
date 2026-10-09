# PwndPass

PwndPass is a client-side password breach checker and cryptographic auditor. It uses the Have I Been Pwned (HIBP) Passwords Range API to check for known breaches while keeping the password and the hash suffix in the browser.

**Live app:** [https://mic-sp.github.io/PwndPass/](https://mic-sp.github.io/PwndPass/)

The project is built with vanilla HTML5, CSS3, and modern JavaScript. It has no package dependencies, external scripts, font downloads, or application backend. The browser makes one HTTPS range request to HIBP for each valid lookup.

## Architecture and Privacy

```text
				 BROWSER (local memory)
  Password entered
	  |
	  v
  TextEncoder -> crypto.subtle.digest("SHA-1")
	  |
	  v
  40-character SHA-1 digest
	  |
	  +-------------------------------+
	  |                               |
	  v                               v
  5-character prefix              35-character suffix
	  |                         remains in browser
	  |                               |
	  v                               |
  HTTPS GET /range/{prefix}             |
	  |                               |
	  v                               |
  HIBP returns candidate suffix:count   |
	  |                               |
	  +---------------+---------------+
				v
		 In-memory suffix comparison
				|
				v
		  Breach result and audit UI
```

For a valid password, PwndPass encodes the input with `TextEncoder` and computes a SHA-1 digest using the browser's native Web Crypto API. It splits the 40-character hexadecimal digest locally. Only the first five hexadecimal characters are included in the HIBP request URL; the plaintext password, complete digest, and remaining 35-character suffix are not sent by the application. HIBP returns matching suffixes and breach counts for that prefix, and the browser compares those candidates against the local suffix in memory.

This is a k-anonymity range-query design, not a formal zero-knowledge protocol. HIBP receives the requested prefix, and the browser/network still expose ordinary request metadata such as the client IP address. The privacy benefit is that the service is not given the password or full hash as part of the lookup. The anonymity set depends on the candidate hashes returned for each prefix.

SHA-1 is used for compatibility with the HIBP range API; it must not be used to store or verify application passwords. The hash shown in the inspector is displayed locally in the page. Like any browser-based tool, PwndPass cannot protect a password from a compromised device, malicious browser extension, or someone viewing the screen.

## Features

- **HIBP Passwords Range API:** Sends the locally calculated five-character SHA-1 prefix to `https://api.pwnedpasswords.com/range/{prefix}` over HTTPS. It checks the HTTP status before reading the response and compares returned suffixes locally.
- **k-Anonymity inspector:** Expands to show the locally calculated hash as a five-character prefix and 35-character suffix. Its Crowd / Pool Size is the number of non-empty candidate lines returned for the prefix. The panel is hidden while a lookup is empty, pending, or unsuccessful.
- **Password visibility toggle:** Switches between masked and visible input with inline SVG eye icons and updates its accessible label.
- **Keyspace entropy:** Detects lowercase letters, uppercase letters, digits, and other characters. The current model uses pool contributions of 26, 26, 10, and 33 respectively. For password length $L$ and estimated pool size $R$, it calculates:

  $$E = L \cdot \log_2(R)$$

- **Offline brute-force estimate:** Estimates exhaustive search time at a fixed baseline of $10^{11}$ guesses per second, representative of a high-end cluster attacking fast hashes such as NTLM or MD5:

  $$T = \frac{R^L}{10^{11}} \text{ seconds}$$

  Results are formatted in seconds, minutes, hours, days, years, or centuries. The computation uses logarithms internally to handle very large keyspaces.
- **Dictionary / combinator heuristic:** Shows an amber alert for passwords at least 12 characters long when the detected character set contains only letters. Long alphabetical phrases may have high theoretical keyspace entropy but remain susceptible to dictionary wordlists and combinator attacks.
- **Responsive terminal interface:** Uses a dark terminal-inspired palette, cyan controls, green clean states, red breach/error states, and an amber pattern warning.

## Estimator Limitations

The entropy figure is a theoretical keyspace estimate that assumes every character is independently and uniformly selected from the detected pool. Human-created passwords and phrases rarely satisfy that assumption. The dictionary/combinator notice is a narrow heuristic: it flags long letters-only inputs, but it does not inspect a dictionary, identify a particular phrase, or model all guessing strategies.

The crack-time figure is an illustrative exhaustive-search model, not a prediction for a specific attacker or stored hash. Actual rates depend on the hash algorithm, hardware, attack strategy, and password structure. Slow password hashing algorithms such as Argon2, scrypt, bcrypt, and PBKDF2 have very different guess rates from fast hashes.

## Running Locally

No build or install step is required. Serve the project root from localhost or use the GitHub Pages deployment. Web Crypto is available in secure contexts such as HTTPS and localhost.

```sh
python3 -m http.server 8000
```

Then open [http://localhost:8000](http://localhost:8000). The browser needs an internet connection to query HIBP; the hashing and analysis calculations run locally.

## Project Files

- `index.html` — semantic page structure and UI controls.
- `style.css` — responsive terminal theme and status styling.
- `script.js` — local hashing, range request, suffix matching, inspector, and strength estimates.

## Git Development History

| Milestone | Commit | Implementation |
| --- | --- | --- |
| Initial repository | `67fa633` | Created the repository and README starter. |
| Local SHA-1 hashing | `686f785` | Added the password form and browser-native Web Crypto hashing. |
| HIBP range request | `a735444` | Sent only the five-character hash prefix to the Range API. |
| Response parsing | `3e326de` | Split the response into suffix/count entries and rendered the match result. |
| Defensive handling | `512fdd1` | Added blank-input guards, progress feedback, and HTTP/network error handling. |
| Cyberpunk UI | `d7c13ff` | Added the responsive terminal interface and dark neon styling. |
| SVG eye toggle | `caa7713` | Added the interactive password visibility control. |
| k-Anonymity breakdown | `16a1162` | Added the query inspector, hash split, and candidate crowd tally. |
| Entropy model and pattern warning | `8ad671d` | Added character-pool entropy, offline crack-time estimates, and the dictionary/combinator heuristic. |
