import { VertexAI } from '@google-cloud/vertexai';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keyFilePath = path.join(__dirname, './vision-ai-455010-d952b6232600.json');
const credentials = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));

async function main() {
  try {
    const vertexAI = new VertexAI({
      project: 'vision-ai-455010',
      location: 'us-central1',
      credentials
    });

    console.log('✅ Vertex AI client initialized successfully in test script!');


    console.log('VertexAI Object:', vertexAI); // Add this line
    // Optionally, try a simple API call (might require further setup)
     const model = vertexAI.preview.generativeModel({ model: 'gemini-pro' });
     const result = await model.generateContent({
       contents: [{ role: 'user', parts: [{ text: 'Hello' }] }],
 });
     console.log('✅ Simple API call successful in test script:', result);

  } catch (error) {
    console.error('❌ Error initializing Vertex AI client in test script:', error);
  }
}

main();