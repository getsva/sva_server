# Environment Configuration Guide

This project uses separate environment files for local development and production.

## Environment Files

- **`.env.local`** - Local development settings (committed to git with safe defaults)
- **`.env.production`** - Production settings (DO NOT commit with real secrets)
- **`.env.example`** - Template file showing all available variables

## How It Works

The Django settings automatically loads the appropriate `.env` file based on the `ENVIRONMENT` variable:

1. **System Environment Variable** (highest priority)
   - Set `ENVIRONMENT=development` or `ENVIRONMENT=production` as a system environment variable
   - Useful for deployment platforms (Azure, Heroku, etc.)

2. **Environment-Specific Files**
   - If `ENVIRONMENT=development` → loads `.env.local`
   - If `ENVIRONMENT=production` → loads `.env.production`

3. **Fallback**
   - Falls back to `.env` if environment-specific file doesn't exist

## Local Development

1. Copy `.env.example` to `.env.local` (if not already created)
2. Update values in `.env.local` with your local settings
3. The app will automatically use `.env.local` when `ENVIRONMENT=development`

```bash
# The .env.local file should have:
ENVIRONMENT=development
```

## Production Deployment

1. Create `.env.production` with your production values
2. **IMPORTANT**: Replace all placeholder values with real secrets
3. Set `ENVIRONMENT=production` in your deployment platform's environment variables
4. Or ensure `.env.production` has `ENVIRONMENT=production`

```bash
# The .env.production file should have:
ENVIRONMENT=production
```

## Setting Environment Variable

### Local Development (macOS/Linux)
```bash
export ENVIRONMENT=development
python manage.py runserver
```

### Local Development (Windows)
```cmd
set ENVIRONMENT=development
python manage.py runserver
```

### Production (Azure App Service)
Set `ENVIRONMENT=production` in Application Settings

### Production (Docker)
```dockerfile
ENV ENVIRONMENT=production
```

## Security Notes

- ✅ `.env.local` can be committed (contains safe development defaults)
- ❌ `.env.production` should NOT be committed with real secrets
- ✅ `.env.example` is safe to commit (template only)
- ✅ All `.env*` files are in `.gitignore` by default

## Quick Switch

To switch between environments locally:

```bash
# Use local development
export ENVIRONMENT=development
python manage.py runserver

# Test production settings locally (be careful!)
export ENVIRONMENT=production
python manage.py runserver
```

## Variables That Auto-Configure

Based on `ENVIRONMENT`, these settings are automatically configured:

- `DEBUG` - True for development, False for production
- `EMAIL_BACKEND` - Console for development, SMTP for production
- Security settings - Production security enabled when `ENVIRONMENT=production`
