


async function sendPushNotification(userId, productId, productName) {

    //const queryParams = new URLSearchParams({ userId: userId, productId:productId });
    console.log("removeFavorite");
    try
    {
        const resp = await fetch(`${url}/removeFavorite/${userId}/${productId}`,
    
        {
          method: 'DELETE',
          headers: {"Content-Type": "application/json"}
      
        }
      
        );


        const data = await resp.json();
        //console.log(data);

        //showToast(`Produkti ${productName} u largua nga te preferuarat tuaja.`);

        }
          catch(e)
        {
          //console.log(e);

        }


  }




  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('https://api.example.com/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });
      const result = await response.json();
      console.log('Success:', result);
    } catch (error) {
      console.error('Error:', error);
    }
  };