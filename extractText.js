import { VertexAI } from '@google-cloud/vertexai';

/**
 * Extracts the latest sale end date from Albanian text using Vertex AI (Gemini).
 * Returns the latest date in YYYY-MM-DD format, or null if not found.
 * Handles multiple dates and ranges.
 * @param {string} text - The Albanian promotional text.
 * @returns {Promise<string|null>} - The extracted date or null.
 */

export async function exctractSaleEndDate(text) {
  // Debug: Input validation
  if (!text || typeof text !== "string" || !text.trim()) {
    console.error("[formatDataToJson] Invalid input text.");
    return null;
  }


  // Debug: Show input text
  console.debug("[formatDataToJson] Extracting date from text:", text);

  // Use environment variables for project and location to match server.js setup
  const vertexAi = new VertexAI({
    project: process.env.GOOGLE_CLOUD_PROJECT,
    location: process.env.GOOGLE_CLOUD_REGION || 'us-central1',
  });

  const model = 'gemini-1.5-pro-002'; // Use the latest Gemini model';
  const currentDate = new Date().toISOString().slice(0, 10);

  // Build the prompt for the LLM
  const prompt =
    "You are an expert at extracting dates from Albanian promotional texts.\n" +
    "1. Find all dates or date ranges in the text (e.g., \"23 Qershor 2025\", \"nga 20-22 Korrik\").\n" +
    "2. If there are multiple dates or a range, return the latest date.\n" +
    "3. If the year is missing, use the current year: " + currentDate.slice(0, 4) + ".\n" +
    "4. Respond ONLY with a JSON object: {\"endDate\": \"YYYY-MM-DD\"} or {\"endDate\": null} if not found.\n" +
    "Text:\n" +
    "---\n" +
    text +
    "\n---\n";

  // Debug: Show the prompt being sent to Vertex AI
  console.debug("[formatDataToJson] Vertex AI prompt:", prompt);

  try {
    const generativeModel = vertexAi.getGenerativeModel({ model });
    const result = await generativeModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }]
    });

    // Debug: Show the raw response from Vertex AI
    const responseText = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
    console.debug("[formatDataToJson] Vertex AI response:", responseText);

    let parsed;
    try {
      parsed = JSON.parse(responseText);
    } catch (err) {
      console.error("[formatDataToJson] Failed to parse Vertex AI response as JSON:", err);
      return null;
    }

    if (
      parsed &&
      typeof parsed === "object" &&
      Object.prototype.hasOwnProperty.call(parsed, "endDate") &&
      (parsed.endDate === null || /^\d{4}-\d{2}-\d{2}$/.test(parsed.endDate))
    ) {
      console.debug("[formatDataToJson] Extracted endDate:", parsed.endDate);
      return parsed.endDate;
    } else {
      console.warn("[formatDataToJson] Vertex AI response missing or invalid endDate.");
      return null;
    }
  } catch (error) {
    console.error("[formatDataToJson] Vertex AI API error:", error);
    return null;
  }
}