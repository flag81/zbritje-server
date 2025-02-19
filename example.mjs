import OpenAI from "openai";
const openai = new OpenAI();




const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: "extract product descriptions along with sale data , sale end date , in Albanian,  from this sales flyer and return the result as json array of objects, for each object containing product data ." },
          {
            type: "image_url",
            image_url: {
              "url": "https://res.cloudinary.com/dt7a4yl1x/image/upload/v1735158414/uploads/ccmainz5m07eguwyipyw.jpg",
            },
          },
        ],
      },
    ],
  });
  
  console.log(response.choices[0]);