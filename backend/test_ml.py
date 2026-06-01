from app.services.ml_service import predict_url

result = predict_url(
    "paypal-login-secure.xyz"
)

print(result)