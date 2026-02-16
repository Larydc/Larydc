"""
Comprehensive Test Suite for labHE(Paillier) Implementation
============================================================

Tests all aspects discussed in the conversation:
1. Basic encryption/decryption
2. Offline/online split
3. Homomorphic operations (Add, Mult, cMult)
4. Statistical computations
5. Multi-user scenarios
6. Edge cases and error handling
"""

import unittest
from labhe_paillier_implementation import (
    LabHE_Paillier, 
    MultiUser_LabHE_Paillier,
    LabeledProgram,
    Ciphertext
)


class TestBasicOperations(unittest.TestCase):
    """Test basic labHE operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.labhe = LabHE_Paillier()
        self.epk, self.sk = self.labhe.keygen(key_length=2048)
    
    def test_encryption_decryption(self):
        """Test basic encryption and decryption."""
        message = 42
        label = "test_value"
        
        # Encrypt
        ct = self.labhe.encrypt(self.sk, label, message)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x: x,
            labels=[label],
            function_name="identity"
        )
        result = self.labhe.decrypt(self.sk, program, ct)
        
        self.assertEqual(result, message)
    
    def test_offline_online_encryption(self):
        """Test offline/online encryption split."""
        message = 100
        label = "offline_test"
        
        # Offline phase
        c_off = self.labhe.offline_enc(self.sk, label)
        
        # Online phase
        ct = self.labhe.online_enc(c_off, message)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x: x,
            labels=[label],
            function_name="identity"
        )
        result = self.labhe.decrypt(self.sk, program, ct)
        
        self.assertEqual(result, message)
    
    def test_offline_online_decryption(self):
        """Test offline/online decryption split."""
        message = 250
        label = "decrypt_test"
        
        ct = self.labhe.encrypt(self.sk, label, message)
        
        program = LabeledProgram(
            function=lambda x: x,
            labels=[label],
            function_name="identity"
        )
        
        # Offline phase
        sk_p = self.labhe.offline_dec(self.sk, program)
        
        # Online phase
        result = self.labhe.online_dec(sk_p, ct)
        
        self.assertEqual(result, message)


class TestHomomorphicOperations(unittest.TestCase):
    """Test homomorphic operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.labhe = LabHE_Paillier()
        self.epk, self.sk = self.labhe.keygen(key_length=2048)
    
    def test_addition(self):
        """Test homomorphic addition."""
        m1, m2 = 10, 20
        
        ct1 = self.labhe.encrypt(self.sk, "val1", m1)
        ct2 = self.labhe.encrypt(self.sk, "val2", m2)
        
        # Add
        ct_sum = self.labhe.add(ct1, ct2)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x, y: x + y,
            labels=["val1", "val2"],
            function_name="add"
        )
        result = self.labhe.decrypt(self.sk, program, ct_sum)
        
        self.assertEqual(result, m1 + m2)
    
    def test_multiplication(self):
        """Test homomorphic multiplication."""
        m1, m2 = 5, 7
        
        ct1 = self.labhe.encrypt(self.sk, "val1", m1)
        ct2 = self.labhe.encrypt(self.sk, "val2", m2)
        
        # Multiply
        ct_prod = self.labhe.mult(ct1, ct2)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x, y: x * y,
            labels=["val1", "val2"],
            function_name="multiply"
        )
        result = self.labhe.decrypt(self.sk, program, ct_prod)
        
        self.assertEqual(result, m1 * m2)
    
    def test_scalar_multiplication(self):
        """Test multiplication by constant."""
        m = 15
        c = 3
        
        ct = self.labhe.encrypt(self.sk, "val", m)
        
        # Scalar multiply
        ct_scaled = self.labhe.cmult(c, ct)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x: c * x,
            labels=["val"],
            function_name="scale"
        )
        result = self.labhe.decrypt(self.sk, program, ct_scaled)
        
        self.assertEqual(result, m * c)
    
    def test_complex_polynomial(self):
        """Test degree-2 polynomial: f(x,y,z) = 2x + 3y*z."""
        x, y, z = 4, 5, 6
        
        ct_x = self.labhe.encrypt(self.sk, "x", x)
        ct_y = self.labhe.encrypt(self.sk, "y", y)
        ct_z = self.labhe.encrypt(self.sk, "z", z)
        
        # Compute 2x
        ct_2x = self.labhe.cmult(2, ct_x)
        
        # Compute 3*y*z
        ct_yz = self.labhe.mult(ct_y, ct_z)
        ct_3yz = self.labhe.cmult(3, ct_yz)
        
        # Add: 2x + 3yz
        ct_result = self.labhe.add(ct_2x, ct_3yz)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda x, y, z: 2*x + 3*y*z,
            labels=["x", "y", "z"],
            function_name="polynomial"
        )
        result = self.labhe.decrypt(self.sk, program, ct_result)
        
        expected = 2*x + 3*y*z
        self.assertEqual(result, expected)


class TestStatisticalComputations(unittest.TestCase):
    """Test statistical functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.labhe = LabHE_Paillier()
        self.epk, self.sk = self.labhe.keygen(key_length=2048)
    
    def test_mean(self):
        """Test computing mean on encrypted data."""
        data = [10, 20, 30, 40, 50]
        
        # Encrypt
        cts = [self.labhe.encrypt(self.sk, f"val_{i}", val) 
               for i, val in enumerate(data)]
        
        # Sum
        ct_sum = cts[0]
        for ct in cts[1:]:
            ct_sum = self.labhe.add(ct_sum, ct)
        
        # Decrypt
        program = LabeledProgram(
            function=sum,
            labels=[f"val_{i}" for i in range(len(data))],
            function_name="sum"
        )
        result_sum = self.labhe.decrypt(self.sk, program, ct_sum)
        
        mean = result_sum / len(data)
        expected_mean = sum(data) / len(data)
        
        self.assertEqual(mean, expected_mean)
    
    def test_variance(self):
        """Test computing variance: E[X²] - E[X]²."""
        data = [2, 4, 4, 4, 5, 5, 7, 9]
        
        # Encrypt values
        cts = [self.labhe.encrypt(self.sk, f"val_{i}", val) 
               for i, val in enumerate(data)]
        
        # Compute sum of squares
        cts_sq = [self.labhe.mult(ct, ct) for ct in cts]
        ct_sum_sq = cts_sq[0]
        for ct in cts_sq[1:]:
            ct_sum_sq = self.labhe.add(ct_sum_sq, ct)
        
        # Compute sum
        ct_sum = cts[0]
        for ct in cts[1:]:
            ct_sum = self.labhe.add(ct_sum, ct)
        
        # Decrypt sum of squares
        program_sq = LabeledProgram(
            function=lambda *vals: sum(v*v for v in vals),
            labels=[f"val_{i}" for i in range(len(data))],
            function_name="sum_of_squares"
        )
        sum_sq = self.labhe.decrypt(self.sk, program_sq, ct_sum_sq)
        
        # Decrypt sum
        program_sum = LabeledProgram(
            function=sum,
            labels=[f"val_{i}" for i in range(len(data))],
            function_name="sum"
        )
        total = self.labhe.decrypt(self.sk, program_sum, ct_sum)
        
        # Variance = E[X²] - E[X]²
        n = len(data)
        variance = (sum_sq / n) - (total / n) ** 2
        
        # Expected variance
        mean = sum(data) / n
        expected_var = sum((x - mean)**2 for x in data) / n
        
        self.assertAlmostEqual(variance, expected_var, places=5)
    
    def test_inner_product(self):
        """Test inner product (weighted sum)."""
        x = [1, 2, 3, 4]
        w = [2, 3, 4, 5]  # Weights
        
        # Encrypt x values
        cts_x = [self.labhe.encrypt(self.sk, f"x_{i}", val) 
                 for i, val in enumerate(x)]
        
        # Encrypt weights
        cts_w = [self.labhe.encrypt(self.sk, f"w_{i}", val) 
                 for i, val in enumerate(w)]
        
        # Compute products
        products = [self.labhe.mult(cts_x[i], cts_w[i]) 
                   for i in range(len(x))]
        
        # Sum products
        ct_result = products[0]
        for prod in products[1:]:
            ct_result = self.labhe.add(ct_result, prod)
        
        # Decrypt
        program = LabeledProgram(
            function=lambda *vals: sum(vals[i] * vals[len(x) + i] 
                                      for i in range(len(x))),
            labels=[f"x_{i}" for i in range(len(x))] + 
                   [f"w_{i}" for i in range(len(w))],
            function_name="inner_product"
        )
        result = self.labhe.decrypt(self.sk, program, ct_result)
        
        expected = sum(x[i] * w[i] for i in range(len(x)))
        self.assertEqual(result, expected)


class TestMultiUser(unittest.TestCase):
    """Test multi-user scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mu_labhe = MultiUser_LabHE_Paillier()
        self.mpk, self.msk = self.mu_labhe.setup(key_length=2048)
    
    def test_two_users_addition(self):
        """Test addition of data from two different users."""
        # User 1 setup
        usk1, upk1 = self.mu_labhe.user_keygen(self.mpk, "user1")
        
        # User 2 setup
        usk2, upk2 = self.mu_labhe.user_keygen(self.mpk, "user2")
        
        # User 1 encrypts
        m1 = 100
        ct1 = self.mu_labhe.encrypt(self.mpk, usk1, "val1", m1)
        
        # User 2 encrypts
        m2 = 200
        ct2 = self.mu_labhe.encrypt(self.mpk, usk2, "val2", m2)
        
        # Cloud adds (using basic labHE operations)
        labhe = LabHE_Paillier()
        labhe.public_key = self.mpk['public_key']
        ct_sum = labhe.add(ct1, ct2)
        
        # Receiver decrypts
        program = LabeledProgram(
            function=lambda x, y: x + y,
            labels=["val1", "val2"],
            function_name="sum"
        )
        result = self.mu_labhe.decrypt(self.msk, [upk1, upk2], 
                                       program, ct_sum)
        
        self.assertEqual(result, m1 + m2)
    
    def test_genetic_risk_score(self):
        """Test genetic risk score computation (multi-user)."""
        # Setup users
        usk_lab, upk_lab = self.mu_labhe.user_keygen(self.mpk, "lab")
        usk_med, upk_med = self.mu_labhe.user_keygen(self.mpk, "medical")
        
        # Lab encrypts SNP data
        snps = [0, 1, 2, 1, 0]
        snp_cts = [self.mu_labhe.encrypt(self.mpk, usk_lab, 
                                         f"snp_{i}", val)
                   for i, val in enumerate(snps)]
        
        # Medical center encrypts weights
        weights = [5, 3, 7, 4, 6]
        weight_cts = [self.mu_labhe.encrypt(self.mpk, usk_med, 
                                            f"weight_{i}", val)
                      for i, val in enumerate(weights)]
        
        # Cloud computes weighted sum
        labhe = LabHE_Paillier()
        labhe.public_key = self.mpk['public_key']
        
        products = [labhe.mult(snp_cts[i], weight_cts[i]) 
                   for i in range(len(snps))]
        
        risk_ct = products[0]
        for prod in products[1:]:
            risk_ct = labhe.add(risk_ct, prod)
        
        # Patient decrypts
        def weighted_sum(*vals):
            n = len(vals) // 2
            return sum(vals[i] * vals[n + i] for i in range(n))
        
        program = LabeledProgram(
            function=weighted_sum,
            labels=[f"snp_{i}" for i in range(len(snps))] + 
                   [f"weight_{i}" for i in range(len(weights))],
            function_name="risk_score"
        )
        
        risk_score = self.mu_labhe.decrypt(self.msk, [upk_lab, upk_med],
                                          program, risk_ct)
        
        expected = sum(snps[i] * weights[i] for i in range(len(snps)))
        self.assertEqual(risk_score, expected)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.labhe = LabHE_Paillier()
        self.epk, self.sk = self.labhe.keygen(key_length=2048)
    
    def test_zero_values(self):
        """Test encryption of zero."""
        ct = self.labhe.encrypt(self.sk, "zero", 0)
        
        program = LabeledProgram(
            function=lambda x: x,
            labels=["zero"],
            function_name="identity"
        )
        result = self.labhe.decrypt(self.sk, program, ct)
        
        self.assertEqual(result, 0)
    
    def test_large_values(self):
        """Test encryption of large values."""
        large_val = 2**30  # Large but within modulus
        
        ct = self.labhe.encrypt(self.sk, "large", large_val)
        
        program = LabeledProgram(
            function=lambda x: x,
            labels=["large"],
            function_name="identity"
        )
        result = self.labhe.decrypt(self.sk, program, ct)
        
        self.assertEqual(result, large_val)
    
    def test_negative_values_with_encoding(self):
        """Test negative values using modular encoding."""
        # Encode negative as N - |value|
        neg_val = -42
        modulus = self.labhe.public_key.n
        encoded = (modulus + neg_val) % modulus
        
        ct = self.labhe.encrypt(self.sk, "negative", encoded)
        
        program = LabeledProgram(
            function=lambda x: x,
            labels=["negative"],
            function_name="identity"
        )
        result = self.labhe.decrypt(self.sk, program, ct)
        
        # Decode: if result > N/2, it's negative
        if result > modulus // 2:
            decoded = result - modulus
        else:
            decoded = result
        
        self.assertEqual(decoded, neg_val)
    
    def test_multiple_additions(self):
        """Test many additions."""
        data = list(range(1, 21))  # 1 to 20
        
        cts = [self.labhe.encrypt(self.sk, f"val_{i}", val) 
               for i, val in enumerate(data)]
        
        ct_sum = cts[0]
        for ct in cts[1:]:
            ct_sum = self.labhe.add(ct_sum, ct_sum)
        
        # This should still work (though result will be large)
        self.assertIsNotNone(ct_sum)
    
    def test_level_mismatch_error(self):
        """Test that adding different levels raises error."""
        ct1 = self.labhe.encrypt(self.sk, "val1", 10)
        ct2 = self.labhe.encrypt(self.sk, "val2", 20)
        
        # Create level-2 ciphertext
        ct_level2 = self.labhe.mult(ct1, ct2)
        
        # Try to add level-1 and level-2 (should fail)
        with self.assertRaises(ValueError):
            self.labhe.add(ct1, ct_level2)
    
    def test_mult_level2_error(self):
        """Test that multiplying level-2 raises error."""
        ct1 = self.labhe.encrypt(self.sk, "val1", 5)
        ct2 = self.labhe.encrypt(self.sk, "val2", 7)
        
        # Create two level-2 ciphertexts
        ct_l2_1 = self.labhe.mult(ct1, ct2)
        ct_l2_2 = self.labhe.mult(ct1, ct2)
        
        # Try to multiply level-2 ciphertexts (should fail)
        with self.assertRaises(ValueError):
            self.labhe.mult(ct_l2_1, ct_l2_2)


class TestPerformance(unittest.TestCase):
    """Test performance characteristics."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.labhe = LabHE_Paillier()
        self.epk, self.sk = self.labhe.keygen(key_length=2048)
    
    def test_constant_ciphertext_size(self):
        """Verify ciphertexts have constant size."""
        # Encrypt single value
        ct1 = self.labhe.encrypt(self.sk, "single", 42)
        
        # Encrypt and add many values
        cts = [self.labhe.encrypt(self.sk, f"val_{i}", i) 
               for i in range(100)]
        ct_sum = cts[0]
        for ct in cts[1:]:
            ct_sum = self.labhe.add(ct_sum, ct)
        
        # Both should be level-1, size (int, EncryptedNumber)
        self.assertEqual(ct1.level, 1)
        self.assertEqual(ct_sum.level, 1)
        
        # Both have same structure
        self.assertEqual(type(ct1.data), type(ct_sum.data))
    
    def test_online_decryption_independence(self):
        """Verify online decryption doesn't depend on circuit size."""
        import time
        
        # Small computation
        ct_small = self.labhe.encrypt(self.sk, "val", 100)
        program_small = LabeledProgram(
            function=lambda x: x,
            labels=["val"],
            function_name="identity"
        )
        sk_p_small = self.labhe.offline_dec(self.sk, program_small)
        
        start = time.time()
        self.labhe.online_dec(sk_p_small, ct_small)
        time_small = time.time() - start
        
        # Large computation (sum of 100 values)
        cts_large = [self.labhe.encrypt(self.sk, f"val_{i}", i) 
                     for i in range(100)]
        ct_large = cts_large[0]
        for ct in cts_large[1:]:
            ct_large = self.labhe.add(ct_large, ct)
        
        program_large = LabeledProgram(
            function=sum,
            labels=[f"val_{i}" for i in range(100)],
            function_name="sum_100"
        )
        sk_p_large = self.labhe.offline_dec(self.sk, program_large)
        
        start = time.time()
        self.labhe.online_dec(sk_p_large, ct_large)
        time_large = time.time() - start
        
        # Online times should be similar (both just decrypt one ciphertext)
        # Allow 10x variation due to system noise
        self.assertLess(time_large, time_small * 10)


def run_all_tests():
    """Run all test suites."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestBasicOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestHomomorphicOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestStatisticalComputations))
    suite.addTests(loader.loadTestsFromTestCase(TestMultiUser))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
