"""
Ransomware Detection & Response System (RDRS) - Shannon Entropy Calculator

Shannon Entropy measures randomness or data unpredictability in a byte stream.
Formula: H(X) = -sum( P(x_i) * log2(P(x_i)) )
- Plain text / source code: ~3.0 to 5.0 bits/byte
- Compiled binaries: ~6.0 to 6.8 bits/byte
- Encrypted or compressed data (Ransomware output): ~7.2 to 8.0 bits/byte (Max 8.0)
"""

import math
from typing import Union, List


def calculate_shannon_entropy(data: Union[bytes, bytearray]) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.

    :param data: Byte sequence to evaluate.
    :return: Entropy score between 0.0 (uniform single byte) and 8.0 (maximum randomness).
    """
    if not data:
        return 0.0

    length = len(data)
    # Count frequency of each byte (0 to 255)
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    for count in frequency:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def calculate_file_entropy(file_path: str, sample_size_bytes: int = 65536) -> float:
    """
    Calculate Shannon entropy of a file by reading up to sample_size_bytes.

    :param file_path: Path to the target file.
    :param sample_size_bytes: Max bytes to read for sample entropy (default 64KB).
    :return: Calculated Shannon entropy (0.0 - 8.0). Returns 0.0 if file is unreadable.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read(sample_size_bytes)
            return calculate_shannon_entropy(data)
    except (FileNotFoundError, PermissionError, OSError):
        return 0.0


def is_suspicious_entropy(entropy: float, threshold: float = 7.2) -> bool:
    """
    Check if the entropy score exceeds the threshold indicative of ransomware encryption.
    """
    return entropy >= threshold
