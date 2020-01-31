# Auth0 for Chrome extensions [DEPRECATED]
[![All Contributors](https://img.shields.io/badge/all_contributors-3-orange.svg?style=flat-square)](#contributors)
<img src="https://img.shields.io/badge/community-driven-brightgreen.svg"/> <br>

### Deprecation notice

This repository has been deprecated.

### Contributors

Thanks goes to these wonderful people who contribute(d) or maintain(ed) this repo ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore -->
<table>
  <tr>
    <td align="center"><a href="https://twitter.com/beardaway"><img src="https://avatars3.githubusercontent.com/u/11062800?v=4" width="100px;" alt="Conrad Sopala"/><br /><sub><b>Conrad Sopala</b></sub></a><br /><a href="#maintenance-beardaway" title="Maintenance">🚧</a> <a href="#review-beardaway" title="Reviewed Pull Requests">👀</a></td>
    <td align="center"><a href="https://github.com/darkyen"><img src="https://avatars1.githubusercontent.com/u/1041315?v=4" width="100px;" alt="Abhishek Hingnikar"/><br /><sub><b>Abhishek Hingnikar</b></sub></a><br /><a href="#review-darkyen" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/auth0-community/auth0-chrome/commits?author=darkyen" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/kirlat"><img src="https://avatars1.githubusercontent.com/u/18631055?v=4" width="100px;" alt="kirlat"/><br /><sub><b>kirlat</b></sub></a><br /><a href="https://github.com/auth0-community/auth0-chrome/commits?author=kirlat" title="Code">💻</a></td>
  </tr>
</table>

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Intro

This package allows you to use Auth0 within a Chrome extension. It provides a generic  `PKCEClient.js`  file which allows you to use the  [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)  spec, which is recommended for native applications.

With this package, you can set up your Chrome extension to use Auth0's hosted  [Lock](https://auth0.com/lock)  widget. It uses the  `launchWebAuthFlow`  from Chrome's identity API to retrieve tokens from Auth0.

This repo is supported and maintained by Community Developers, not Auth0. For more information about different support levels check https://auth0.com/docs/support/matrix .

## Getting started

If you haven't already done so, [sign up](https://auth0.com/signup) for your free Auth0 account and create an application in the dashboard. Find the **domain** and **client ID** from your app settings, as these will be required to integrate Auth0 in your Chrome extension. Note that the client type that you use has to be `Native`, or you will get unauthorized errors.

Chrome extensions are packaged as `.crx` files for distribution but may be loaded "unpacked" for development. For more information on how to load an unpacked extension, see the [Chrome extension docs](https://developer.chrome.com/extensions/getstarted#unpacked).

When loading your application as an unpacked extension, a unique ID will be generated for it. You must whitelist your callback URL (the URL that Auth0 will return to once authentication is complete) and the allowed origin URL.

In the **Allowed Callback URLs** section, whitelist your callback URL.

```bash
https://<YOUR_APP_ID>.chromiumapp.org/auth0
```

In the **Allowed Origins** section, whitelist your chrome extension as an origin.

```bash
chrome-extension://<YOUR_APP_ID>
```

### Installation


Install the `auth0-chrome` package with npm.

```bash
npm install auth0-chrome
```

The `dist` folder contains a webpack bundle, including a minified version.

Configure your `manifest.json` file to run the `auth0chrome` script, along with an `env.js` and `main.js` script for your project. The `default_popup` should be set to an HTML file containing the content you would like to display.

```js
{
  ...
  "browser_action": {
    "default_title": "Auth0",
    "default_popup": "src/browser_action/browser_action.html"
  },
  "background": {
    "scripts": ["./env.js", "node_modules/auth0-chrome/dist/auth0chrome.min.js", "src/main.js"],
    "persistent": false
  },
  "permissions": [
    "identity",
    "notifications"
  ]
}
```

Add your Auth0 credentials in the `env.js` file.

```js
window.env = {
  AUTH0_DOMAIN: 'YOUR_AUTH0_DOMAIN',
  AUTH0_CLIENT_ID: 'YOUR_AUTH0_CLIENT_ID',
};
```

## Usage

### Login

Somewhere in your browser action, create a **Log In** button and when it is clicked, emit an event that can be picked up to trigger the authentication flow. For example, listen for click events with jQuery and emit a message called `authenticate` with `chrome.runtime.sendMessage`.

```js
// ...
  $('.login-button').addEventListener('click', () => {
    $('.default').classList.add('hidden');
    $('.loading').classList.remove('hidden');
    chrome.runtime.sendMessage({
      type: "authenticate"
    });
  });
// ...
```

Your `main.js` file is where you should add the listener for the `authenticate` event. This is where you can instantiate `Auth0Chrome` and call the `authenticate` method to start the flow and save the authentication result when it comes back.

```js
// src/main.js

chrome.runtime.onMessage.addListener(function (event) {
  if (event.type === 'authenticate') {

    // scope
    //  - openid if you want an id_token returned
    //  - offline_access if you want a refresh_token returned
    // device
    //  - required if requesting the offline_access scope.
    let options = {
      scope: 'openid offline_access',
      device: 'chrome-extension'
    };

    new Auth0Chrome(env.AUTH0_DOMAIN, env.AUTH0_CLIENT_ID)
      .authenticate(options)
      .then(function (authResult) {
        localStorage.authResult = JSON.stringify(authResult);
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: 'Login Successful',
          message: 'You can use the app now'
        });
      }).catch(function (err) {
      chrome.notifications.create({
        type: 'basic',
        title: 'Login Failed',
        message: err.message,
        iconUrl: 'icons/icon128.png'
      });
    });
  }
});
```

Auth0's hosted Lock widget will be displayed in a new window.

![auth0 lock](https://cdn.auth0.com/blog/auth0-chrome-lock.png)

### Styling

To apply styles to the login page, go to your Auth0 account and go to [Hosted Pages](https://manage.auth0.com/#/login_page). From there toggle "Customize Login Page", that will allow you to not only customize the Lock widget, but also apply some styling to the page.

To read more on this go to [Customize Your Hosted Page](https://auth0.com/docs/hosted-pages#customize-your-hosted-page).

### Using the Library

* Auth0Chrome(domain, clientId)

    The library exposes `Auth0Chrome` which extends a generic `PKCEClient`.

    - `domain` : Your Auth0 Domain, to create one please visit https://auth0.com/
    - `clientId`: The clientId for the chrome client, to create one
    - Visit https://manage.auth0.com/#/clients and click on  `+ Create Application`
    - Select "Native" as the client type
    - In the **Allowed Callback URLs** section, add `https://<yourchromeappid>.chromiumapp.org/auth0` as an allowed callback url
    - In the **Allowed Origins** section, add `chrome-extension://<yourchromeappid>`

* Promise <Object> Auth0Client#authenticate(options, interactive)

    The `authenticate` method makes a call to the Authentication API and renders the login UI if `userinteraction` is required. Upon completion, this method will resolve an object which will contain the requested token and meta information related to the authentication process.

    - `options`: `object` - accepts all the parameters valid for [Auth0's Authentication API](https://auth0.com/docs/api/authentication/) except for `redirect_uri`, `response_type`, `code_challenge` & `code_challenge_method` as these are controlled by the library

    - `interactive`: `boolean` - if set to `false` for advanced use-cases, Chrome will throw an error if user-interaction is required during login

    The `access_token` returned at the end of the authentication flow can then be used to make authenticated calls to your API. For more information on using access tokens, see the [full documentation](https://auth0.com/docs/api-auth).


## Contribute

Feel like contributing to this repo? We're glad to hear that! Before you start contributing please visit our [Contributing Guideline](https://github.com/auth0-community/getting-started/blob/master/CONTRIBUTION.md).

Here you can also find the [PR template](https://github.com/auth0-community/auth0-chrome/blob/master/PULL_REQUEST_TEMPLATE.md) to fill once creating a PR. It will automatically appear once you open a pull request.

### Development

Install the dev dependencies.

```bash
npm install
```

When changes are made, run `npm run build` to produce new files for the `dist` folder.

## Issues Reporting

Spotted a bug or any other kind of issue? We're just humans and we're always waiting for constructive feedback! Check our section on how to [report issues](https://github.com/auth0-community/getting-started/blob/master/CONTRIBUTION.md#issues)!

Here you can also find the [Issue template](https://github.com/auth0-community/auth0-chrome/blob/master/ISSUE_TEMPLATE.md) to fill once opening a new issue. It will automatically appear once you create an issue.

## Repo Community

Feel like PRs and issues are not enough? Want to dive into further discussion about the tool? We created topics for each Auth0 Community repo so that you can join discussion on stack available on our repos. Here it is for this one: [auth0-chrome](https://community.auth0.com/t/auth0-community-oss-auth0-chrome/15985)

<a href="https://community.auth0.com/">
<img src="/assets/join_auth0_community_badge.png"/>
</a>

## License

This project is licensed under the MIT license. See the [LICENSE](https://github.com/auth0-community/auth0-chrome/blob/master/LICENSE) file for more info.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like
  * Google
  * Facebook
  * Microsoft
  * Linkedin
  * GitHub
  * Twitter
  * Box
  * Salesforce
  * etc.

  **or** enterprise identity systems like:
  * Windows Azure AD
  * Google Apps
  * Active Directory
  * ADFS
  * Any SAML Identity Provider

* Add authentication through more traditional [username/password databases](https://docs.auth0.com/mysql-connection-tutorial)
* Add support for [linking different user accounts](https://docs.auth0.com/link-accounts) with the same user
* Support for generating signed [JSON Web Tokens](https://docs.auth0.com/jwt) to call your APIs and create user identity flow securely
* Analytics of how, when and where users are logging in
* Pull data from other sources and add it to user profile, through [JavaScript rules](https://docs.auth0.com/rules)

## Create a free Auth0 account

* Go to [Auth0 website](https://auth0.com/signup)
* Hit the **SIGN UP** button in the upper-right corner
