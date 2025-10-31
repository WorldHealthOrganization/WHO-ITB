echo Deploying test suite...
del hcert-vhl.zip
7z a hcert-vhl.zip .\testsuites\hcert-vhl\*
del hcert-icvp.zip
7z a hcert-icvp.zip .\testsuites\hcert-icvp\*
del hcert-signature.zip
7z a hcert-signature.zip .\testsuites\hcert-signature\*


curl -F updateSpecification=true -F specification=6DEAC9D3XB479X4A4CXADC5X68BA94006701 -F testSuite=@hcert-vhl.zip --header "ITB_API_KEY: 2E86828DXEDB9X4C5CX8D5DX5BF0A406DAB9" -X POST http://localhost:10003/api/rest/testsuite/deploy
curl -F updateSpecification=true -F specification=6DEAC9D3XB479X4A4CXADC5X68BA94006701 -F testSuite=@hcert-icvp.zip --header "ITB_API_KEY: 2E86828DXEDB9X4C5CX8D5DX5BF0A406DAB9" -X POST http://localhost:10003/api/rest/testsuite/deploy
curl -F updateSpecification=true -F specification=6DEAC9D3XB479X4A4CXADC5X68BA94006701 -F testSuite=@hcert-signature.zip --header "ITB_API_KEY: 2E86828DXEDB9X4C5CX8D5DX5BF0A406DAB9" -X POST http://localhost:10003/api/rest/testsuite/deploy
