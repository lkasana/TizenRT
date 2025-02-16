/****************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
// command, type, handler
SL_CRYPTO_TEST_POOL("aes_dec",   SL_CRYPTO_TYPE_AES_DECRYPT, sl_handle_crypto_aes_dec)
SL_CRYPTO_TEST_POOL("aes_enc",   SL_CRYPTO_TYPE_AES_ENCRYPT, sl_handle_crypto_aes_enc)
SL_CRYPTO_TEST_POOL("rsa_dec",   SL_CRYPTO_TYPE_RSA_DECRYPT, sl_handle_crypto_rsa_dec)
SL_CRYPTO_TEST_POOL("rsa_enc",   SL_CRYPTO_TYPE_RSA_ENCRYPT, sl_handle_crypto_rsa_enc)
