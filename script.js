const passwordForm = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");
const resultElement = document.querySelector("#result");
const passwordToggle = document.querySelector("#password-toggle");
const queryInspector = document.querySelector("#query-inspector");
const queryHashPrefix = document.querySelector("#query-hash-prefix");
const queryHashSuffix = document.querySelector("#query-hash-suffix");
const queryPoolSize = document.querySelector("#query-pool-size");

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  queryInspector.hidden = true;

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
  } catch {
    // Keep request and hashing failures distinct from a clean lookup result.
    queryInspector.hidden = true;
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
