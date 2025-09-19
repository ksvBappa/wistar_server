const jwt = require('jsonwebtoken');
const SECRET_KEY = "sT0dHCZ3aG9cxw2j";

// Signing the JWT
const token = jwt.sign({ userId: 4 }, SECRET_KEY, {
  algorithm: 'HS256', 
  issuer: 'make-my-book-autht', 
  audience: 'make-my-book-api', // Set audience
  expiresIn: '24h', // You can add expiry if needed
});

console.log("Generated Token:", token);

// Verifying the JWT
try {

  const decoded = jwt.verify("Yfy9mIb9Av4EmxpPAXGaeOkkVsHy0ZNL1QhFBwTHlzlk6gAY6VKu1XzlqobfiFhM4PIQYEUzDQOvSEWf2mwJfnzYKJRQ-Lk9jGX-gUq8GcyjuzgSDkuC2e1-ab7e_WLLmlAF9BczKwkqxG_8lqpONpdA8evef2BZI9yx4eq19xCha3VFbjHN-LxsNGB8mBZJiCxzfw_D2TjJ_CPcNeSi4luEsX2geSyq4pSId1n66a9RZhT2d8uma8FJvPNk2gftdLFC1HhYnpyhB74oYHNHS8978G9uIykjLpxDzDvH2eYfSo7ub1X5iOuF74of_hTdsfAs6dvLMzQVuHm0Z9DAKg", SECRET_KEY);

  console.log("Decoded Token:", decoded);
} catch (err) {
  console.error("Token verification failed:", err.message);
}
