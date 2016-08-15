# 1password.js

`1password.js` is a library to process 1password Vaults. 

## Installation

You can install via npm:

```
> npm install 1password-js
```

## Usage

`1password.js` exposes a class that is instantiated with the vault master password and optionally, the profile name, and can be searched with the `search` method:

```js
const Vault = require('1password-js');

// Somehow we get the master password...

const vault = new Vault(masterPassword);

// Or, supplying a profile name:

const vault = new Vault(masterPassword, 'my-special-profile');

// Searching in the Vault
// `.search` return a Promise that will resolve to the item detail(s)
// or reject
vault.search('Github').then(items => {
	// The search may have multiple entries
	const password = items[0].itemDetail.fields.find(field => field.designation === 'password').value;
}).catch(() => {
	// There wasn't anything found with that title
})
```

## Notes

This only currently works on Mac. If you have the location of the vault sqlite database on other systems, create an issue and I'll add it!

## License

MIT