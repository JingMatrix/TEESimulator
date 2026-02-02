DEBUG=false

MODDIR=${0%/*}

cd $MODDIR

while true; do
  ./daemon "$MODDIR"
  # ensure keystore initialized
  sleep 2
done &
