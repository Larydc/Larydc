import csv
import time
import random
from collections import defaultdict
from math import gcd

# ===========================
# Utility: Miller-Rabin primality testing and prime generation
# ===========================
def is_probable_prime(n, k=40):
    if n < 2:
        return False
    # small primes
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^r
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    # Miller-Rabin
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip = False
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                skip = True
                break
        if skip:
            continue
        return False
    return True

def generate_prime(bits):
    assert bits >= 16
    while True:
        candidate = random.getrandbits(bits)
        # ensure odd and set MSB, LSB to make correct bit-length and odd
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def lcm(a, b):
    return a // gcd(a, b) * b

def modinv(a, m):
    # Extended Euclidean Algorithm
    def egcd(x, y):
        if y == 0:
            return (x, 1, 0)
        g, s, t = egcd(y, x % y)
        return (g, t, s - (x // y) * t)
    g, s, t = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return s % m

# ===========================
# Paillier cryptosystem (pure Python)
# ===========================
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n2 = n * n

class PaillierPrivateKey:
    def __init__(self, n, lam, mu):
        self.n = n
        self.lam = lam
        self.mu = mu
        self.n2 = n * n

class PaillierKeypair:
    def __init__(self, bits=128):
        half = bits // 2
        # generate distinct primes p and q
        p = generate_prime(half)
        q = generate_prime(half)
        while q == p:
            q = generate_prime(half)
        n = p * q
        g = n + 1  # common choice
        lam = lcm(p - 1, q - 1)
        # compute mu = (L(g^lam mod n^2))^{-1} mod n
        def L(u):
            return (u - 1) // n
        u = pow(g, lam, n * n)
        mu = modinv(L(u), n)
        self.pub = PaillierPublicKey(n, g)
        self.priv = PaillierPrivateKey(n, lam, mu)

    def encrypt(self, m):
        if m < 0 or m >= self.pub.n:
            raise ValueError("plaintext out of range (must be in [0, n-1])")
        # random r in Z*_n
        while True:
            r = random.randrange(1, self.pub.n)
            if gcd(r, self.pub.n) == 1:
                break
        # c = g^m * r^n mod n^2
        c1 = pow(self.pub.g, m, self.pub.n2)
        c2 = pow(r, self.pub.n, self.pub.n2)
        return (c1 * c2) % self.pub.n2

    def decrypt(self, c):
        def L(u):
            return (u - 1) // self.priv.n
        u = pow(c, self.priv.lam, self.priv.n2)
        m = (L(u) * self.priv.mu) % self.priv.n
        return m

    # Homomorphic sum (ciphertext multiply)
    def add(self, ciphertexts):
        res = 1
        for c in ciphertexts:
            res = (res * c) % self.pub.n2
        return res

    # Constant multiplication (ciphertext exponent)
    def cmul(self, c, k):
        if k < 0:
            raise ValueError("negative scalar not supported in this simple variant")
        return pow(c, k, self.pub.n2)

# ===========================
# Data handling (CSV: node_id, production)
# ===========================
def load_dataset(csv_path, sample_rows=None):
    data = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Expect 'node_id' and 'production' columns
            if 'node_id' not in row or 'production' not in row:
                raise ValueError("CSV must contain 'node_id' and 'production' columns.")
            try:
                node = str(row['node_id'])
                prod = row['production']
                # Convert production to integer; if float, scale to preserve precision
                if '.' in prod:
                    # scale example: 1000x to keep 3 decimals
                    m = int(round(float(prod) * 1000))
                else:
                    m = int(prod)
            except Exception:
                # skip bad rows
                continue
            data.append((node, m))
            if sample_rows is not None and len(data) >= sample_rows:
                break
    return data

def partition_by_nodes(data, max_nodes=None):
    groups = defaultdict(list)
    for node, m in data:
        groups[node].append(m)
    # limit number of nodes if requested
    if max_nodes is not None and len(groups) > max_nodes:
        limited = defaultdict(list)
        for idx, (node, vals) in enumerate(groups.items()):
            limited[node] = vals
            if idx + 1 >= max_nodes:
                break
        return limited
    return groups

# ===========================
# Benchmarks: KeyGen, Enc (per record), Server Eval (sum), Dec (per result)
# ===========================
def benchmark_keygen(bits=128, repeats=3):
    times_ms = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        kp = PaillierKeypair(bits=bits)
        t1 = time.perf_counter()
        times_ms.append((t1 - t0) * 1000.0)
    avg = sum(times_ms) / len(times_ms)
    return avg, times_ms

def benchmark_encrypt_groups(groups, kp):
    enc_avg_per_node = {}
    cipher_groups = defaultdict(list)
    for node, values in groups.items():
        enc_times = []
        for m in values:
            # Map plain m to [0, n-1]; for large m, consider modulo n, but we assume data small
            t0 = time.perf_counter()
            c = kp.encrypt(m)
            t1 = time.perf_counter()
            enc_times.append((t1 - t0) * 1000.0)
            cipher_groups[node].append(c)
        enc_avg_per_node[node] = sum(enc_times) / len(enc_times) if enc_times else 0.0
    return enc_avg_per_node, cipher_groups

def server_eval_sum(cipher_groups, kp):
    results = {}
    for node, c_list in cipher_groups.items():
        t0 = time.perf_counter()
        c_sum = kp.add(c_list)
        t1 = time.perf_counter()
        results[node] = (c_sum, (t1 - t0) * 1000.0)
    return results

def benchmark_decrypt_results(sum_results, kp):
    dec_times = []
    plain_sums = {}
    for node, (c_sum, _) in sum_results.items():
        t0 = time.perf_counter()
        m_sum = kp.decrypt(c_sum)
        t1 = time.perf_counter()
        dec_times.append((t1 - t0) * 1000.0)
        plain_sums[node] = m_sum
    avg_dec = sum(dec_times) / len(dec_times) if dec_times else 0.0
    return avg_dec, dec_times, plain_sums

# ===========================
# Experiment runner
# ===========================
def run_experiment(csv_path,
                   sample_rows=5000,
                   node_counts=(10, 50, 100, 200),
                   moduli=(256, 128)):
    raw = load_dataset(csv_path, sample_rows=sample_rows)
    print(f"Loaded {len(raw)} rows (sample)")

    reports = []

    for bits in moduli:
        print(f"\n=== Security parameter: {bits}-bit ===")
        keygen_avg, keygen_all = benchmark_keygen(bits=bits, repeats=3)
        print(f"KeyGen avg: {keygen_avg:.2f} ms; runs: {[f'{t:.2f}' for t in keygen_all]}")

        # Use one keypair per modulus run (single-user)
        kp = PaillierKeypair(bits=bits)

        for n_nodes in node_counts:
            print(f"\n-- Nodes: {n_nodes} --")
            groups = partition_by_nodes(raw, max_nodes=n_nodes)
            print(f"Nodes in run: {len(groups)}")

            enc_avg_per_node, cipher_groups = benchmark_encrypt_groups(groups, kp)
            # summarize enc
            enc_node_avgs = list(enc_avg_per_node.values())
            enc_overall_avg = sum(enc_node_avgs) / len(enc_node_avgs) if enc_node_avgs else 0.0
            print(f"Enc avg per-node: {enc_overall_avg:.3f} ms")

            # server sum eval
            sum_results = server_eval_sum(cipher_groups, kp)
            eval_avgs = [t for (_, t) in sum_results.values()]
            eval_overall_avg = sum(eval_avgs) / len(eval_avgs) if eval_avgs else 0.0
            print(f"Server sum Eval avg per-node: {eval_overall_avg:.3f} ms")

            # decrypt
            dec_avg, dec_times, plain_sums = benchmark_decrypt_results(sum_results, kp)
            print(f"Dec avg per result: {dec_avg:.3f} ms")

            # collect report for this configuration
            reports.append({
                "bits": bits,
                "nodes": n_nodes,
                "keygen_avg_ms": keygen_avg,
                "enc_avg_ms_per_node_overall": enc_overall_avg,
                "server_sum_eval_avg_ms_per_node": eval_overall_avg,
                "dec_avg_ms_per_result": dec_avg,
                # optional detailed metrics (can be large):
                # "enc_avg_ms_per_node": enc_avg_per_node,
                # "server_sum_eval_ms_per_node": {node: t for node, (_, t) in sum_results.items()},
                # "sum_plain_results": plain_sums,
            })
    return reports

# ===========================
# Main entry
# ===========================
if __name__ == "__main__":
    # Configure these parameters
    CSV_PATH = "energy_production.csv"  # set your file path
    SAMPLE_ROWS = 5000                  # adjust sample size
    NODE_COUNTS = (10, 50, 100, 200)    # adjust per dataset size
    MODULI = (256, 128)               # requested test sizes

    # Run experiments
    try:
        results = run_experiment(
            csv_path=CSV_PATH,
            sample_rows=SAMPLE_ROWS,
            node_counts=NODE_COUNTS,
            moduli=MODULI
        )
        print("\nSummary:")
        for r in results:
            print(f"bits={r['bits']}, nodes={r['nodes']}, "
                  f"KeyGen={r['keygen_avg_ms']:.2f} ms, "
                  f"Enc/node={r['enc_avg_ms_per_node_overall']:.3f} ms, "
                  f"Eval/node={r['server_sum_eval_avg_ms_per_node']:.3f} ms, "
                  f"Dec/result={r['dec_avg_ms_per_result']:.3f} ms")
    except Exception as e:
        print(f"Error: {e}")
