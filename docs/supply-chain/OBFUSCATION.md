# Obfuscation & Entropy Analysis Specification

This document details the entropy scoring methodology and obfuscation detection algorithms utilized in `SC-OBF-001` and `SC-OBF-002`.

---

## 1. Shannon Entropy Formula

The Shannon Entropy $H(S)$ of a string $S$ measures the average information density and randomness of characters within the literal:

$$H(S) = - \sum_{c \in \Sigma} p(c) \log_2 p(c)$$

Where:

- $\Sigma$ is the set of unique code points in $S$.
- $p(c) = \frac{\text{count}(c)}{|S|}$ is the empirical probability of character $c$ occurring in $S$.

### Boundary Properties

- For an empty string: $H = 0$.
- For a string of identical characters (e.g. `"AAAAAA"`): $H = 0$.
- For normal English code comments: $H \approx 2.5 - 3.8$.
- For base64-encoded binary payloads: $H \ge 4.5$ (typically $5.0 - 5.8$).
- For encrypted random byte arrays: $H \approx 6.0$.

---

## 2. Detection Algorithm (`SC-OBF-001`)

To prevent false alarms on identifiers, ordinary strings, or short hashes, literals are evaluated through a multi-stage gate:

1. **Extraction**: String literals are extracted from JavaScript/TypeScript/Python source files (quotes, template literals).
2. **Length Gate**: The string literal length $|S|$ must satisfy $|S| \ge 64$ characters.
3. **Entropy Gate**: The computed Shannon entropy must satisfy $H(S) \ge 4.5$.
4. **Charset Gate**: The string must match either Base64 or Hex character distributions:
   - Base64: `^[A-Za-z0-9+/=_-]+$`
   - Hexadecimal: `^[0-9a-fA-F]+$`
5. **False Positive Exclusions**:
   - Subresource Integrity (SRI) hashes (`sha256-...`, `sha384-...`, `sha512-...`).
   - Inline Data URIs (`data:image/...`, `data:application/...`).
   - Source mapping URLs (`sourceMappingURL=data:...`).
   - Standard UUID strings (`[0-9a-f]{8}-[0-9a-f]{4}-...`).
   - Known license texts and legal disclaimers.

---

## 3. Unbroken Line Obfuscation (`SC-OBF-002`)

Attackers often insert minified single-line payload loaders inside otherwise standard files.

- **Criteria**: Any source code line with length $> 1000$ characters containing zero whitespace or very low token entropy is flagged as suspicious packing (`SC-OBF-002`).
