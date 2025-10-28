export const config = { runtime: "nodejs" };

export default async function handler(req, res) {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing ?url=" });

  try {
    const resp = await fetch(url, { redirect: "follow" });
    return res.json({ finalUrl: resp.url, status: resp.status });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
}
