const passwordForm = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");

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

  console.log("SHA-1 prefix:", prefix);
  console.log("SHA-1 suffix:", suffix);
});
