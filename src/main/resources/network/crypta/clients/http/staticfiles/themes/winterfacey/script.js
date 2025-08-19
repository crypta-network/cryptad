var mobileMenu = function() {

  // initial main variables
  var navbarDomElement = document.getElementById('navbar');
  var navlistDomElement = document.getElementById('navlist');
  var hamburgerDomElement;
  var activeClass = 'active';
  var hamburgerId = 'hamburger-box';
  var hamburgerContent = document.createElement('div');


  hamburgerContent.id = hamburgerId;
  hamburgerContent.innerHTML = '<span></span><span></span><span></span><span></span>';

  // function toggle class for old browser
  function toggleClass(element, className){
    if (!element || !className){
        return;
    }

    var classString = element.className, nameIndex = classString.indexOf(className);
    if (nameIndex == -1) {
        classString += ' ' + className;
    }
    else {
        classString = classString.substr(0, nameIndex) + classString.substr(nameIndex+className.length);
    }
    element.className = classString;
  }

  // function for check element in page
  function customAddEventListener(element, eventName, fn) {
    if (element) {
      element.addEventListener(eventName, fn);
    }
  }

  function customRemoveEventListener(element, eventName, fn) {
    if (element) {
      element.removeEventListener(eventName, fn);
    }
  }

  function hasClass(element, cssClass) {
    if (element) {
      return element.className.match(new RegExp('(\\s|^)' + cssClass + '(\\s|$)'));
    }
  }

  function removeClass(element, cssClass) {
      if (hasClass(element, cssClass) && element) {
          var reg = new RegExp('(\\s|^)'+ cssClass +'(\\s|$)');
          element.className = element.className.replace(reg,' ');
      }
  }

  function removeElement(elementId) {
    var element = document.getElementById(elementId);

    if (element) {
      element.parentNode.removeChild(element);
    }
  }

  function toggleCssClasses() {
    toggleClass(navlistDomElement, activeClass);
    toggleClass(hamburgerDomElement, activeClass)
  }

  function attach() {
    navbarDomElement.appendChild(hamburgerContent);
    hamburgerDomElement = document.getElementById(hamburgerId);
    customAddEventListener(hamburgerDomElement, 'click', toggleCssClasses);
  }

  function detach() {
    removeClass(navlistDomElement, activeClass);
    removeClass(hamburgerDomElement, activeClass);
    customRemoveEventListener(hamburgerDomElement, 'click', toggleCssClasses);
    removeElement(hamburgerId);
  }

  function ready() {
    if ( window.innerWidth < 991 ) {
      attach()
    } else {
      detach()
    }
  }

  ready();
  window.onresize = function(e) { ready() };
};

var toggleInnerMenu = function() {
  var selectedList = document.querySelectorAll('#navlist > .navlist-selected');
  var selectedLinkList = document.querySelectorAll('#navlist > .navlist-selected > a');
  var notSelectedList = document.querySelectorAll('#navlist > .navlist-not-selected');
  var notSelectedLinkList = document.querySelectorAll('#navlist > .navlist-not-selected > a');

  // add active class for selected element after load page
  selectedList[0].className += " active";

  // function toggle (add and remove active class)
  function toggle(selectedItem) {
    if (selectedItem.className.search(/active/i) != -1) {
      selectedItem.className = selectedItem.className.replace(/(?:^|\s)active(?!\S)/g, '' )
    } else {
      selectedItem.className += " active";
    }
  }
  
  function handleClick(clickedClass, changedClass) {
    for (var i = 0; i < clickedClass.length; i++) {
      (function(i){
        clickedClass[i].addEventListener('click', function(event) {
          if ( window.innerWidth < 991 ) {
            event.preventDefault();
            toggle(changedClass[i]);
          }
        });
      })(i)
    }
  }

  function ready() {
    handleClick(selectedLinkList, selectedList);
    handleClick(notSelectedLinkList, notSelectedList);
  }

  ready();
}

function removeSizeFromInput () {
  var inputs = document.getElementsByTagName('input');

  for(var i = 0; i < inputs.length; i++) {
    if(inputs[i].type.toLowerCase() == 'text') {
        inputs[i].removeAttribute('size');
    }
  }
} 

var addTagMetaViewport = function() {
  var meta = document.createElement('meta');

  meta.name = "viewport";
  meta.content = "width=device-width, initial-scale=1;";
  document.getElementsByTagName('head')[0].appendChild(meta);
}

// Make logo clickable - redirects to the same link as "Browsing" menu
var makeLogoClickable = function() {
  var navbarElement = document.getElementById('navbar');
  
  if (navbarElement) {
    // Find the Browsing menu link dynamically
    var browsingLink = document.querySelector('#navlist li a[href]');
    var browsingHref = browsingLink ? browsingLink.href : '/';
    
    // Create a wrapper around the logo pseudo-element area
    var logoWrapper = document.createElement('a');
    logoWrapper.className = 'logo-link';
    logoWrapper.href = browsingHref;  // Same as Browsing menu link (dynamic)
    logoWrapper.title = 'Browse Crypta';
    logoWrapper.style.cssText = 'position: absolute; left: 0; width: 40px; height: 40px; margin-right: 20px; cursor: pointer; z-index: 10000;';
    
    // Position the logo link based on the navbar's position
    navbarElement.style.position = 'relative';
    
    // Insert the logo link as the first child of navbar
    navbarElement.insertBefore(logoWrapper, navbarElement.firstChild);
    
    // Adjust positioning to cover the :before pseudo-element
    var updateLogoPosition = function() {
      // Get the computed style to find where the :before element is
      var navbarRect = navbarElement.getBoundingClientRect();
      var styles = window.getComputedStyle(navbarElement, ':before');
      
      // Position the clickable area over the logo
      // Account for flexbox centering
      var navlistElement = document.getElementById('navlist');
      if (navlistElement) {
        var navlistRect = navlistElement.getBoundingClientRect();
        // Logo is 20px to the left of navlist (margin-right: 20px)
        logoWrapper.style.left = (navlistRect.left - navbarRect.left - 60) + 'px';
      }
    };
    
    // Update position on load and resize
    updateLogoPosition();
    window.addEventListener('resize', updateLogoPosition);
  }
};

document.addEventListener("DOMContentLoaded", addTagMetaViewport);
document.addEventListener('DOMContentLoaded', removeSizeFromInput);
document.addEventListener("DOMContentLoaded", mobileMenu);
document.addEventListener('DOMContentLoaded', toggleInnerMenu);
document.addEventListener('DOMContentLoaded', makeLogoClickable);


