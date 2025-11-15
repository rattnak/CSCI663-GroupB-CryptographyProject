import { useState } from "react";

const API_BASE_URL = "http://localhost:5000/api";

function App() {
  const [algorithm, setAlgorithm] = useState("aes"); // 'aes' or 'rsa'
  const [mode, setMode] = useState("encrypt");
  const [key, setKey] = useState("");
  const [keySize, setKeySize] = useState(128);
  const [rsaKeySize, setRsaKeySize] = useState(2048);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleProcess = async () => {
    setError("");
    setOutput("");

    if (!key.trim()) {
      setError("Please enter a key");
      return;
    }

    if (!input.trim()) {
      setError("Please enter text to process");
      return;
    }

    setLoading(true);

    try {
      if (algorithm === "aes") {
        // AES
        setError("AES backend not yet implemented.");
      } else {
        // RSA
        setError("RSA backend not yet implemented.");
      }
    } catch (err) {
      setError(
        `Error: ${err.message}. Make sure the Flask API is running on port 5000.`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setKey("");
    setInput("");
    setOutput("");
    setError("");
  };

  const handleAlgorithmChange = (newAlgorithm) => {
    setAlgorithm(newAlgorithm);
    handleClear();
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">
            Cryptography Demo
          </h1>
          <p className="text-sm text-gray-600">
            Encrypt and decrypt text using AES or RSA
          </p>
        </div>

        {/* Algorithm Tabs */}
        <div className="mb-4">
          <div className="flex border-b border-gray-200">
            <button
              onClick={() => handleAlgorithmChange("aes")}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                algorithm === "aes"
                  ? "border-gray-900 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              AES (Symmetric)
            </button>
            <button
              onClick={() => handleAlgorithmChange("rsa")}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                algorithm === "rsa"
                  ? "border-gray-900 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              RSA (Asymmetric)
            </button>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded p-6 space-y-5">
          {/* Mode Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Mode
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setMode("encrypt")}
                className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                  mode === "encrypt"
                    ? "bg-gray-900 text-white"
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                Encrypt
              </button>
              <button
                onClick={() => setMode("decrypt")}
                className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                  mode === "decrypt"
                    ? "bg-gray-900 text-white"
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                Decrypt
              </button>
            </div>
          </div>

          {/* Key Size Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Key Size
            </label>
            <select
              value={keySize}
              onChange={(e) => setKeySize(parseInt(e.target.value))}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none bg-white"
            >
              <option value={128}>AES-128 (16 bytes, 10 rounds)</option>
              <option value={192}>AES-192 (24 bytes, 12 rounds)</option>
              <option value={256}>AES-256 (32 bytes, 14 rounds)</option>
            </select>
          </div>

          {/* Key Input */}
          <div>
            <label
              htmlFor="key"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              {algorithm === "aes"
                ? "Key"
                : mode === "encrypt"
                ? "Public Key"
                : "Private Key"}
            </label>
            <textarea
              id="key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={
                algorithm === "aes"
                  ? "Enter encryption key"
                  : mode === "encrypt"
                  ? "Enter public key (PEM format)"
                  : "Enter private key (PEM format)"
              }
              rows={algorithm === "rsa" ? "4" : "1"}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-none font-mono"
            />
          </div>

          {/* Input Text */}
          <div>
            <label
              htmlFor="input"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              {mode === "encrypt" ? "Plaintext" : "Ciphertext"}
            </label>
            <textarea
              id="input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                mode === "encrypt"
                  ? "Enter text to encrypt"
                  : "Enter text to decrypt"
              }
              rows="4"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-none"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleProcess}
              disabled={loading}
              className="flex-1 bg-gray-900 text-white py-2 px-4 text-sm font-medium rounded hover:bg-gray-800 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading
                ? "Processing..."
                : mode === "encrypt"
                ? "Encrypt"
                : "Decrypt"}
            </button>
            <button
              onClick={handleClear}
              disabled={loading}
              className="px-4 py-2 text-sm font-medium bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition disabled:bg-gray-50 disabled:cursor-not-allowed"
            >
              Clear
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          {/* Output */}
          {output && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {mode === "encrypt" ? "Encrypted" : "Decrypted"}
              </label>
              <div className="bg-gray-50 border border-gray-200 rounded p-3">
                <p className="font-mono text-xs break-all text-gray-800">
                  {output}
                </p>
              </div>
              <button
                onClick={() => navigator.clipboard.writeText(output)}
                className="mt-2 text-xs text-gray-600 hover:text-gray-900 underline"
              >
                Copy to clipboard
              </button>
            </div>
          )}

          {/* Info */}
          <div className="pt-4 border-t border-gray-200">
            <p className="text-xs text-gray-500 mb-2">
              {algorithm === "aes" ? "AES Details:" : "RSA Details:"}
            </p>
            {algorithm === "aes" ? (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>AES-128/192/256 symmetric encryption</li>
                <li>Custom Python implementation via Flask API</li>
                <li>SubBytes, ShiftRows, MixColumns transformations</li>
                <li>PKCS7 padding, variable rounds (10/12/14)</li>
                <li>Key sizes: 16/24/32 bytes for 128/192/256-bit</li>
              </ul>
            ) : (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>RSA asymmetric encryption (public/private key pair)</li>
                <li>Backend implementation coming soon</li>
                <li>Encrypt with public key, decrypt with private key</li>
                <li>Key sizes: 1024/2048/4096-bit</li>
                <li>Based on prime factorization difficulty</li>
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
