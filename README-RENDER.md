# Deploy to Render (Alternative Option)

Render is another great alternative to AWS Lightsail with a generous free tier.

## Quick Setup (5 minutes)

### 1. Create Render Account
- Go to [render.com](https://render.com)
- Sign up with GitHub (free)

### 2. Deploy Your App
- Click "New +" → "Web Service"
- Connect your GitHub repository
- Render auto-detects the Dockerfile
- Click "Create Web Service"

### 3. Configuration
Render will auto-detect most settings, but verify:
- **Build Command**: `docker build -t app .`
- **Start Command**: `docker run -p 10000:3000 app`
- **Port**: 3000 (internal), 10000 (external)

### 4. Get Your URL
- Render provides a free `.onrender.com` subdomain
- Example: `https://openid-server-abcd.onrender.com`

### 5. Test Your Deployment
```bash
# Replace with your actual Render URL
curl https://your-app.onrender.com/health
curl https://your-app.onrender.com/.well-known/openid-configuration
```

## Cost
- **Free tier**: 750 hours/month (enough for development)
- **Paid tier**: $7/month (always-on, faster builds)

## Benefits vs AWS Lightsail
- ✅ No AWS credentials needed
- ✅ Automatic HTTPS/SSL
- ✅ Auto-deploys from Git commits
- ✅ Built-in monitoring and logs
- ✅ Free tier available
- ✅ Simple environment variables
- ✅ Easy rollbacks

## Environment Variables (Optional)
If you need custom settings:
- Go to your service dashboard
- Click "Environment" tab
- Add key-value pairs

## Custom Domain (Optional)
- Go to "Settings" → "Custom Domains"
- Add your domain
- Render handles SSL automatically

## Note about Free Tier
- Services spin down after 15 minutes of inactivity
- First request after spin-down takes ~30 seconds
- Upgrade to paid tier for always-on service 