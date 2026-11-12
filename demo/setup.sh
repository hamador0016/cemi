# Prepares the project shown in demo.tape. Every value here is made up.
# The debug build keeps the unlock session in a folder and uses a fast key derivation,
# so the recording does not wait on the system keyring or on Argon2id.
export CEMI_HOME=/tmp/cemi-demo/vault
export CEMI_TEST_SESSION_DIR=/tmp/cemi-demo/session
export CEMI_INSECURE_FAST_KDF=1
export PS1='\[\e[1;36m\]~/code/shop\[\e[0m\] $ '

mkdir -p ~/code/shop
cd ~/code/shop || return
git init -q

# Built in two parts so secret scanners do not take the fake key for a real one
fake_key="sk_""test_51Hx9demoK3yN0tR3al00000000"
printf 'STRIPE_KEY=%s\nDATABASE_URL=postgres://app:hunter2@db.internal:5432/shop\n' "$fake_key" > .env

cat > app.sh <<'EOF'
#!/bin/sh
echo "Starting shop on :3000"
echo "debug: STRIPE_KEY=$STRIPE_KEY"
echo "debug: DATABASE_URL=$DATABASE_URL"
EOF
chmod +x app.sh

printf 'demo-password-123\ndemo-password-123\n' | cemi --password-stdin init --global >/dev/null 2>&1
