import { VertexAI } from '@google-cloud/vertexai';
import path from 'path';
import { fileURLToPath } from 'url';

// Resolve directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Set authentication environment variable
const keyFilePath = path.join(__dirname, './vision-ai-455010-d952b6232600.json');
process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFilePath;

// ✅ Initialize Vertex AI
const vertexAI = new VertexAI({
  project: 'vision-ai-455010',
  location: 'us-central1'
});

// ✅ Access Generative Model (e.g., Gemini 1.5 Pro)
const generativeModel = vertexAI.getGenerativeModel({
  model: 'gemini-1.5-pro'
});

// ✅ Function to Send a Prompt to Gemini
async function askGemini(promptText) {
  try {
    const response = await generativeModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: promptText }] }]
    });

    // ✅ Debugging: Log full response structure
    console.log('📌 Raw API Response:', JSON.stringify(response, null, 2));

    // ✅ Check if response contains valid candidates
    if (!response.candidates || response.candidates.length === 0) {
      throw new Error('No response candidates found.');
    }

    // ✅ Extract Response Text Safely
    const responseText = response.candidates[0]?.content?.parts?.[0]?.text ?? "No valid response received.";

    console.log('✅ Gemini Response:', responseText);
    return responseText;

  } catch (error) {
    console.error('❌ Error calling Gemini API:', error);
  }
}

// ✅ Example Usage
const userPrompt = "Summarize the latest AI advancements.";
askGemini(userPrompt);
