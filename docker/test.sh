docker run \
    -e "OPINE_ENV=docker" \
    --rm \
    -v "$(pwd)/../":/app opine:phpunit-user \
    --bootstrap /app/tests/bootstrap.php
