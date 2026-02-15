# Fly.io Deployment (zikirmatik)

## 1) Fly CLI kurulum ve login
```bash
brew install flyctl
fly auth login
```

## 2) App olusturma (bir kez)
```bash
cd /Users/aselamt/zikirmatik
fly apps create zikirmatik
```

## 3) Kalici volume olusturma (SQLite icin)
```bash
fly volumes create zikir_data --size 1 --region ams --app zikirmatik
```

## 4) Gizli degiskenleri ayarla
```bash
fly secrets set \
  SESSION_SECRET="guclu-bir-rastgele-secret" \
  ADMIN_USERNAME="admin" \
  ADMIN_PASSWORD="guclu-admin-sifre" \
  --app zikirmatik
```

## 5) Deploy
```bash
fly deploy --app zikirmatik
```

## 6) Ac
```bash
fly open --app zikirmatik
```

## Notlar
- `DATABASE_PATH` ve `SESSION_DB_DIR` Fly volume uzerindeki `/data` klasorune yazacak sekilde ayarlandi.
- `SESSION_SECRET` uretim ortaminda zorunlu olarak degistirilmeli.
