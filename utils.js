// **NEW Function to group text elements spatially**
export function groupTextElementsSpatially(pages) {
  const productBlocks = [];
  const VERTICAL_THRESHOLD = 15; // Adjust based on your flyers' line spacing
  const HORIZONTAL_THRESHOLD = 20; // Adjust based on spacing between elements in a product entry

  pages.forEach(page => {
    // Flatten all words with their bounding boxes and text
    const wordsWithBoxes = [];
    page.blocks.forEach(block => {
      block.paragraphs.forEach(paragraph => {
        paragraph.words.forEach(word => {
          wordsWithBoxes.push({
            text: word.symbols.map(s => s.text).join(''),
            boundingBox: word.boundingBox,
            centerY: (word.boundingBox.vertices[0].y + word.boundingBox.vertices[2].y) / 2,
            centerX: (word.boundingBox.vertices[0].x + word.boundingBox.vertices[1].x) / 2,
            height: word.boundingBox.vertices[2].y - word.boundingBox.vertices[0].y,
            width: word.boundingBox.vertices[1].x - word.boundingBox.vertices[0].x,
          });
        });
      });
    });

    // Sort words primarily by vertical position, then by horizontal position
    wordsWithBoxes.sort((a, b) => {
      if (a.centerY !== b.centerY) {
        return a.centerY - b.centerY;
      }
      return a.centerX - b.centerX;
    });

    // Simple grouping into lines based on vertical proximity
    const lines = [];
    if (wordsWithBoxes.length > 0) {
      let currentLine = [wordsWithBoxes[0]];
      for (let i = 1; i < wordsWithBoxes.length; i++) {
        const word = wordsWithBoxes[i];
        const lastWordInLine = currentLine[currentLine.length - 1];
         const verticalDistance = Math.abs(word.centerY - lastWordInLine.centerY);
        const horizontalDistance = word.centerX - lastWordInLine.centerX - lastWordInLine.width; // Distance from end of last word to center of current

        // If words are vertically close OR horizontally close enough to be on the same conceptual line
        if (verticalDistance < VERTICAL_THRESHOLD && horizontalDistance < HORIZONTAL_THRESHOLD * 3) { // Adjusted horizontal check
           currentLine.push(word);
        } else {
          lines.push(currentLine);
          currentLine = [word];
        }
      }
      if (currentLine.length > 0) {
        lines.push(currentLine);
      }
    }
    

    // Further grouping of lines into potential product blocks
    let currentProductBlock = [];
    if (lines.length > 0) {
      currentProductBlock.push(lines[0]);
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const lastLineInBlock = currentProductBlock[currentProductBlock.length - 1];
        
        // Calculate vertical distance between the current line and the last line in the block
        const lastLineBottom = lastLineInBlock.reduce((maxY, word) => Math.max(maxY, word.boundingBox.vertices[2].y), -1);
        const currentLineTop = line.reduce((minY, word) => Math.min(minY, word.boundingBox.vertices[0].y), Infinity);
        const verticalDistance = currentLineTop - lastLineBottom;

        // Check for a significant vertical gap or if the line contains typical product info (prices, keywords)
        // This logic needs refinement based on your flyer structure
         const lineText = line.map(word => word.text).join(' ');
         const isPriceOrDescription = /[0-9€€.]/.test(lineText) || lineText.toLowerCase().includes('kg') || lineText.toLowerCase().includes('l'); // Basic heuristic

        if (verticalDistance < VERTICAL_THRESHOLD * 2 || isPriceOrDescription) { // Group lines that are vertically close or contain price/description clues
           currentProductBlock.push(line);
        } else {
          productBlocks.push(currentProductBlock);
          currentProductBlock = [line];
        }
      }
      if (currentProductBlock.length > 0) {
        productBlocks.push(currentProductBlock);
      }
    }

  });

  // Format for Gemini: an array of blocks, each containing lines with text and bounding boxes
   const formattedBlocks = productBlocks.map(block => ({
     lines: block.map(line => ({
       text: line.map(word => word.text).join(' '),
       // Optional: Include bounding box for the whole line if needed by prompt
       // boundingBox: { vertices: [ { x: Math.min(...line.map(w => w.boundingBox.vertices[0].x)), y: Math.min(...line.map(w => w.boundingBox.vertices[0].y)) }, ... ] }
     }))
   }));


  return formattedBlocks; // Return the spatially grouped data
}
