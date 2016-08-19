angular.module('jahia.saml2', ['ngMaterial', 'ngSanitize', 'ngRoute'])
  .config(function ($mdThemingProvider) {
    // theme used to create error toast
    $mdThemingProvider.theme('alert');
  });
