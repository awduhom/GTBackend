require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.json());

const APP_ID = process.env.OCULUS_APP_ID;    
const APP_SECRET = process.env.OCULUS_SECRET; 
const JWT_SECRET = process.env.JWT_SECRET;

app.post('/api/login', async (req, res) => {
    const { userId, nonce } = req.body;
    
    if (!userId || !nonce) {
        return res.status(400).json({ error: "Missing userId or nonce" });
    }
    
    try {
        const appAccessToken = `OC|${APP_ID}|${APP_SECRET}`;
        const metaResponse = await axios.post('https://graph.oculus.com/user_nonce_validate', null, {
            params: {
                access_token: appAccessToken,
                nonce: nonce,
                user_id: userId
            }
        });
        
        if (metaResponse.data.is_valid === true) {
            const token = jwt.sign({ 
                uid: userId, 
                scope: "player" 
            }, JWT_SECRET, { expiresIn: '6h' });
            
            console.log(`Verified User ${userId}. Issued Token.`);
            return res.json({ token: token }); 
        } else {
            console.log(`Failed verification for ${userId}`);
            return res.status(401).json({ error: "Invalid Entitlement" });
        }
    } catch (error) {
        console.error("Meta API Error:", error.response ? error.response.data : error.message);
        return res.status(500).json({ error: "Verification Failed" });
    }
});

app.post('/api/photon-auth', (req, res) => {
    const clientToken = req.body.token || req.query.token;
    
    if (!clientToken) {
        return res.json({ 
            ResultCode: 2, 
            Message: "Missing Session Token" 
        });
    }
    
    try {
        const decoded = jwt.verify(clientToken, JWT_SECRET);
        
        return res.json({ 
            ResultCode: 0,
            Message: "Success",
            UserId: decoded.uid
        });
    } catch (err) {
        console.error("Token verification failed:", err.message);
        
        return res.json({ 
            ResultCode: 1, 
            Message: "Invalid or Expired Token" 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
