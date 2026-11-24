/**
 * Small helper that asks the AI model to explain a scan in plain English.
 * "Telemetry" below just means: the facts we collected during the scan.
 */
import { timeout } from "./scan-engine.server";

export async function explainScan(
  kind: string,
  payload: unknown,
  errors: string[],
): Promise<{ explanation: string | null; recommendations: string[] } | null> {
  const key = process.env.LOVABLE_API_KEY;
  if (!key) return null;

  const res = await timeout(
    fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", "Lovable-API-Key": key, "X-Lovable-AIG-SDK": "fetch" },
      body: JSON.stringify({
        model: "google/gemini-3.5-flash",
        messages: [
          {
            role: "system",
            content:
              `You are a senior SOC analyst reviewing a ${kind} scan. Reply with strict JSON: ` +
              '{"explanation": string (2-4 sentences of simple English citing the strongest evidence), ' +
              '"recommendations": string[] (4-7 concrete prioritised actions)}. No markdown.',
          },
          { role: "user", content: JSON.stringify(payload) },
        ],
        response_format: { type: "json_object" },
      }),
    }).then(async (r) => {
      if (!r.ok) throw new Error(`gateway ${r.status}: ${(await r.text()).slice(0, 200)}`);
      return r.json();
    }),
    20000, "ai-explain", errors,
  );

  const content = (res as any)?.choices?.[0]?.message?.content;
  if (!content) return null;
  try {
    const parsed = JSON.parse(content);
    return {
      explanation: typeof parsed.explanation === "string" ? parsed.explanation : null,
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations.map(String).slice(0, 8) : [],
    };
  } catch {
    errors.push("ai-explain: unparsable response");
    return null;
  }
}
