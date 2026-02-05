# 🚀 Deploy to Render (FREE)

## Step 1: Push to GitHub
```bash
git add .
git commit -m "Ready for Render deployment"
git push origin main
```

## Step 2: Deploy Backend
1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Configure:
   - **Name**: xxe-xlsx-backend
   - **Root Directory**: backend
   - **Environment**: Python 3
   - **Build Command**: pip install -r requirements.txt
   - **Start Command**: gunicorn --bind 0.0.0.0:$PORT app:app
   - **Plan**: Free
6. Click "Create Web Service"
7. **Copy the backend URL** (e.g., https://xxe-xlsx-backend.onrender.com)

## Step 3: Deploy Frontend
1. Click "New +" → "Static Site"
2. Connect same GitHub repo
3. Configure:
   - **Name**: xxe-xlsx-frontend
   - **Root Directory**: frontend
   - **Build Command**: npm install && npm run build
   - **Publish Directory**: build
   - **Environment Variables**:
     - Key: `REACT_APP_API_URL`
     - Value: `https://your-backend-url.onrender.com` (from Step 2)
4. Click "Create Static Site"

## Step 4: Test
- Frontend URL: https://xxe-xlsx-frontend.onrender.com
- Backend URL: https://xxe-xlsx-backend.onrender.com/api/health

## 🎉 Share with Classmates
Send them the frontend URL to test your project!

## ⚠️ Important Notes
- First request may take 30 seconds (free tier sleeps)
- Both services stay active for 750 hours/month (FREE)
- Perfect for college projects!