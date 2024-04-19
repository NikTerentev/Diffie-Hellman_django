class DiffieHellman {
    constructor(keySize = 32) {
        this.keySize = keySize;
        this.p = bigInt.randBetween(bigInt(2).pow(this.keySize), bigInt(2).pow(this.keySize + 1));
        this.g = bigInt.randBetween(bigInt(2), this.p.minus(bigInt.one));
        //console.log(this.p);
        //console.log(this.g);
        this.privateKey = bigInt.randBetween(bigInt(2), this.p.minus(bigInt.one));
        this.publicKey = this.g.modPow(this.privateKey, this.p);
    }

    computeSecret(partnerPublicKey) {
        return bigInt(partnerPublicKey).modPow(this.privateKey, this.p)
    }
}

document.getElementById('registrationForm').addEventListener('submit', function (event) {
    event.preventDefault();

    var username = document.getElementById('id_username').value;
    var password = document.getElementById('id_password').value;
    var password2 = document.getElementById('id_password2').value;

    if (password !== password2) {
        alert('Password missmatch');
        document.getElementById('id_password2').value = '';
        event.preventDefault();
        return;
    }

    const diffieHellman = new DiffieHellman();

    const publicKeyClient = diffieHellman.publicKey.toString();

    fetch('/account/get_dh_data/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.getElementsByName('csrfmiddlewaretoken')[0].value
        },
        body: JSON.stringify({
            publicKeyClient: publicKeyClient,
            p: diffieHellman.p.toString(),
            g: diffieHellman.g.toString()
        })
    })
        .then(response => response.json())
        .then(data => {
            var sharedSecretKey = diffieHellman.computeSecret(data.serverPublicKey);
            var encryptedUsername = CryptoJS.AES.encrypt(username, sharedSecretKey.toString());
            var encryptedPassword = CryptoJS.AES.encrypt(password, sharedSecretKey.toString());
            document.getElementById('id_username').value = encryptedUsername;
            document.getElementById('id_password').value = encryptedPassword;
            document.getElementById('id_password2').value = encryptedPassword;

            document.getElementById('registrationForm').submit();
        })
});

// Если есть сообщение об ошибке, очистить поле username
if (document.querySelector('.errorlist')) {
    document.getElementById('id_username').value = '';
}