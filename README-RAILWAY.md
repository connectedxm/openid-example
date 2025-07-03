# Deploy to Railway (Easiest Option)

Railway is the simplest way to deploy your OpenID server. No complex AWS setup required!

## Quick Setup (5 minutes)

### 1. Create Railway Account
- Go to [railway.app](https://railway.app)
- Sign up with GitHub (free)

### 2. Deploy Your App
- Click "Deploy from GitHub repo"
- Select this repository
- Railway automatically detects the Dockerfile and builds your app
- Your app will be live in ~2 minutes!

### 3. Get Your URL
- Railway provides a free `.railway.app` subdomain
- Example: `https://openid-server-production-abcd.up.railway.app`

### 4. Test Your Deployment
```bash
# Replace with your actual Railway URL
curl https://your-app.railway.app/health
curl https://your-app.railway.app/.well-known/openid-configuration
```

## Cost
- **Free tier**: 500 hours/month (enough for development)
- **Paid tier**: $5/month (unlimited usage)

## Benefits vs AWS Lightsail
- ✅ No AWS credentials needed
- ✅ Automatic HTTPS/SSL
- ✅ Auto-deploys from Git commits
- ✅ Built-in monitoring and logs
- ✅ Simple environment variables
- ✅ One-click rollbacks
- ✅ No Docker push/pull complexity

## Alternative: One-Click Deploy

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template)

Just click the button above and Railway will:
1. Fork this repo to your GitHub
2. Deploy it automatically
3. Give you a live URL

## Environment Variables (Optional)
If you need custom settings:
- Go to your Railway project
- Click "Variables" tab
- Add any environment variables you need

## Custom Domain (Optional)
- Go to "Settings" → "Domains"
- Add your custom domain
- Railway handles SSL automatically

That's it! Much simpler than AWS Lightsail. 