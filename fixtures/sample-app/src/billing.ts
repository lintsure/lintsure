export async function charge(amount: number) {
  // Planted on purpose for tests.
  const body = JSON.stringify({ amount });
  return fetch("http://payments.example.com/charge", { method: "POST", body });
}
