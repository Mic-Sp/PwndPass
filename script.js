const passwordForm = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");
const resultElement = document.querySelector("#result");

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();

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
  const responseText = await response.text();
  const normalizedSuffix = suffix.toUpperCase();
  let breachCount = null;

  // Split each API line into its suffix and count, then compare the suffix exactly.
  for (const line of responseText.split("\n")) {
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
});
