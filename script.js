const passwordForm = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");
const resultElement = document.querySelector("#result");
const passwordToggle = document.querySelector("#password-toggle");
const queryInspector = document.querySelector("#query-inspector");
const queryHashPrefix = document.querySelector("#query-hash-prefix");
const queryHashSuffix = document.querySelector("#query-hash-suffix");
const queryPoolSize = document.querySelector("#query-pool-size");
const strengthPanel = document.querySelector("#strength-panel");
const strengthEntropy = document.querySelector("#strength-entropy");
const strengthPool = document.querySelector("#strength-pool");
const strengthTime = document.querySelector("#strength-time");
const strengthWarning = document.createElement("p");
strengthWarning.className = "strength-panel__warning";
strengthWarning.textContent = "⚠️ Pattern Alert: Long alphabetical phrases have high keyspace entropy, but are vulnerable to dictionary wordlist and combinator attacks.";
strengthWarning.setAttribute("role", "note");
strengthWarning.hidden = true;
strengthTime.parentElement.append(strengthWarning);

// Detect the ASCII character classes represented in a password.
function detectCharacterPool(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;
  return poolSize;
}

// Calculate keyspace entropy using password length and active pool size.
function calculateEntropy(passwordLength, poolSize) {
  return passwordLength * Math.log2(poolSize);
}

// Format crack time from log-space so large keyspaces do not overflow.
function formatCrackTime(passwordLength, poolSize) {
  const log2Seconds = passwordLength * Math.log2(poolSize) - Math.log2(1e11);
  if (log2Seconds < 0) return "Instant (< 1 sec)";

  const units = [
    { label: "seconds", seconds: 1, limit: 60 },
    { label: "minutes", seconds: 60, limit: 60 },
    { label: "hours", seconds: 3600, limit: 24 },
    { label: "days", seconds: 86400, limit: 365 },
    { label: "years", seconds: 31536000, limit: 100 },
  ];

  for (const unit of units) {
    const log2Count = log2Seconds - Math.log2(unit.seconds);
    if (log2Count < Math.log2(unit.limit)) {
      const count = Number((2 ** log2Count).toPrecision(2));
      return `${count} ${unit.label}`;
    }
  }

  return "Centuries";
}

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  queryInspector.hidden = true;
  strengthPanel.hidden = true;

  // Stop empty or whitespace-only input before hashing.
  if (passwordInput.value.trim() === "") {
    resultElement.textContent = "Please enter a valid password.";
    return;
  }

  // Replace any stale result while the lookup is in progress.
  resultElement.textContent = "Verifying...";

  try {
    const passwordBytes = new TextEncoder().encode(passwordInput.value);
    const hashBuffer = await crypto.subtle.digest("SHA-1", passwordBytes);

    // View the digest buffer as individual bytes.
    const hashBytes = Array.from(new Uint8Array(hashBuffer));
    // Convert each byte to two lowercase hexadecimal characters.
    const hashHex = hashBytes
      .map((byte) => byte.toString(16).padStart(2, "0"))
      // Join the hexadecimal byte pairs into the 40-character hash.
      .join("");

    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    // Send only the five-character prefix to the range endpoint.
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    // Reject HTTP errors before interpreting the body as breach data.
    if (!response.ok) {
      throw new Error(`Range request failed with status ${response.status}.`);
    }
    const responseText = await response.text();
    const responseLines = responseText.split("\n");
    const crowdPoolSize = responseLines.filter(Boolean).length;
    const normalizedSuffix = suffix.toUpperCase();
    let breachCount = null;

    // Split each API line into its suffix and count, then compare the suffix exactly.
    for (const line of responseLines) {
      const [apiSuffix, count] = line.split(":");
      if (apiSuffix === normalizedSuffix) {
        breachCount = count.trim();
        break;
      }
    }

    if (breachCount !== null) {
      resultElement.textContent = `Found in breaches: ${breachCount}.`;
    } else {
      resultElement.textContent = "No breaches found (0 occurrences).";
    }

    // Render the audit details only after the response is successfully parsed.
    queryHashPrefix.textContent = prefix;
    queryHashSuffix.textContent = suffix;
    queryPoolSize.textContent = crowdPoolSize.toLocaleString();
    queryInspector.hidden = false;

    const passwordLength = Array.from(passwordInput.value).length;
    const characterPoolSize = detectCharacterPool(passwordInput.value);
    const entropyBits = calculateEntropy(passwordLength, characterPoolSize);
    const containsDigits = /[0-9]/.test(passwordInput.value);
    const containsSymbols = /[^a-zA-Z0-9]/.test(passwordInput.value);

    // Render strength metrics only after the API query succeeds.
    strengthEntropy.textContent = `${entropyBits.toFixed(1)} bits`;
    strengthPool.textContent = characterPoolSize.toLocaleString();
    strengthTime.textContent = formatCrackTime(passwordLength, characterPoolSize);
    // Show the dictionary/combinator warning for long, letters-only inputs.
    strengthWarning.hidden = !(
      passwordLength >= 12 &&
      characterPoolSize <= 52 &&
      !containsDigits &&
      !containsSymbols
    );
    strengthPanel.hidden = false;
  } catch {
    // Keep request and hashing failures distinct from a clean lookup result.
    queryInspector.hidden = true;
    strengthPanel.hidden = true;
    resultElement.textContent = "Unable to verify password. Please try again.";
  }
});

// Swap the input type and matching icon/label to reflect password visibility.
passwordToggle.addEventListener("click", () => {
  const isPasswordVisible = passwordInput.type === "text";
  passwordInput.type = isPasswordVisible ? "password" : "text";

  const toggleLabel = isPasswordVisible ? "Show password" : "Hide password";
  passwordToggle.setAttribute("aria-label", toggleLabel);
  passwordToggle.setAttribute("title", toggleLabel);
  passwordToggle.setAttribute("aria-pressed", String(!isPasswordVisible));
  passwordToggle.classList.toggle("is-visible", !isPasswordVisible);
});
