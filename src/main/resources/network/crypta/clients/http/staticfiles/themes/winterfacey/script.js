/**
 * Mobile menu functionality module
 * Handles responsive hamburger menu toggle at 991px breakpoint
 */
const MobileMenuModule = (() => {
  // Private constants
  const ACTIVE_CLASS = 'active';
  const HAMBURGER_ID = 'hamburger-box';
  const MOBILE_BREAKPOINT = 991;
  
  // DOM element references
  let navbarElement = null;
  let navlistElement = null;
  let hamburgerElement = null;
  let hamburgerContent = null;
  let resizeHandler = null;

  /**
   * Toggles CSS class on element using modern classList API
   * @param {HTMLElement} element - Target element
   * @param {string} className - Class name to toggle
   */
  const toggleClass = (element, className) => {
    element?.classList.toggle(className);
  };

  /**
   * Adds event listener with null check
   * @param {HTMLElement} element - Target element
   * @param {string} eventName - Event type
   * @param {Function} handler - Event handler function
   */
  const safeAddEventListener = (element, eventName, handler) => {
    element?.addEventListener(eventName, handler);
  };

  /**
   * Removes event listener with null check
   * @param {HTMLElement} element - Target element
   * @param {string} eventName - Event type
   * @param {Function} handler - Event handler function
   */
  const safeRemoveEventListener = (element, eventName, handler) => {
    element?.removeEventListener(eventName, handler);
  };

  /**
   * Removes CSS class using modern classList API
   * @param {HTMLElement} element - Target element
   * @param {string} className - Class name to remove
   */
  const removeClass = (element, className) => {
    element?.classList.remove(className);
  };

  /**
   * Removes element from DOM safely
   * @param {string} elementId - ID of element to remove
   */
  const removeElement = (elementId) => {
    const element = document.getElementById(elementId);
    element?.remove();
  };

  /**
   * Creates hamburger menu HTML structure
   * @returns {HTMLElement} Hamburger menu element
   */
  const createHamburgerElement = () => {
    const element = document.createElement('div');
    element.id = HAMBURGER_ID;
    element.innerHTML = '<span></span><span></span><span></span><span></span>';
    return element;
  };

  /**
   * Toggles active class on navigation elements
   */
  const toggleNavigationClasses = () => {
    toggleClass(navlistElement, ACTIVE_CLASS);
    toggleClass(hamburgerElement, ACTIVE_CLASS);
  };

  /**
   * Attaches hamburger menu to mobile layout
   */
  const attachMobileMenu = () => {
    if (!navbarElement || !hamburgerContent) return;
    
    navbarElement.appendChild(hamburgerContent);
    hamburgerElement = document.getElementById(HAMBURGER_ID);
    safeAddEventListener(hamburgerElement, 'click', toggleNavigationClasses);
  };

  /**
   * Detaches hamburger menu from desktop layout
   */
  const detachMobileMenu = () => {
    removeClass(navlistElement, ACTIVE_CLASS);
    removeClass(hamburgerElement, ACTIVE_CLASS);
    safeRemoveEventListener(hamburgerElement, 'click', toggleNavigationClasses);
    removeElement(HAMBURGER_ID);
    hamburgerElement = null;
  };

  /**
   * Handles responsive menu state based on window width
   */
  const handleResponsiveMenu = () => {
    if (window.innerWidth < MOBILE_BREAKPOINT) {
      attachMobileMenu();
    } else {
      detachMobileMenu();
    }
  };

  /**
   * Initializes mobile menu functionality
   */
  const init = () => {
    // Cache DOM elements
    navbarElement = document.getElementById('navbar');
    navlistElement = document.getElementById('navlist');
    
    if (!navbarElement || !navlistElement) {
      console.warn('Mobile menu: Required navigation elements not found');
      return;
    }

    // Create hamburger element once
    hamburgerContent = createHamburgerElement();
    
    // Set up resize handler
    resizeHandler = () => handleResponsiveMenu();
    
    // Initial setup
    handleResponsiveMenu();
    window.addEventListener('resize', resizeHandler);
  };

  /**
   * Cleanup function for removing event listeners
   */
  const destroy = () => {
    if (resizeHandler) {
      window.removeEventListener('resize', resizeHandler);
      resizeHandler = null;
    }
    detachMobileMenu();
  };

  return { init, destroy };
})();

/**
 * Inner menu toggle functionality module
 * Handles dropdown navigation menu toggles in mobile view
 */
const InnerMenuModule = (() => {
  const ACTIVE_CLASS = 'active';
  const MOBILE_BREAKPOINT = 991;

  // Selectors for navigation elements
  const SELECTORS = {
    selectedItems: '#navlist > .navlist-selected',
    selectedLinks: '#navlist > .navlist-selected > a',
    notSelectedItems: '#navlist > .navlist-not-selected',
    notSelectedLinks: '#navlist > .navlist-not-selected > a'
  };

  /**
   * Toggles active class on element using modern classList API
   * @param {HTMLElement} element - Element to toggle class on
   */
  const toggleActiveClass = (element) => {
    element?.classList.toggle(ACTIVE_CLASS);
  };

  /**
   * Sets up click handlers for navigation items
   * @param {NodeList} clickableElements - Elements that trigger the toggle
   * @param {NodeList} targetElements - Elements that get toggled
   */
  const setupClickHandlers = (clickableElements, targetElements) => {
    clickableElements.forEach((clickElement, index) => {
      const targetElement = targetElements[index];
      
      if (!targetElement) return;

      clickElement.addEventListener('click', (event) => {
        if (window.innerWidth < MOBILE_BREAKPOINT) {
          event.preventDefault();
          toggleActiveClass(targetElement);
        }
      });
    });
  };

  /**
   * Initializes the first selected item as active
   * @param {NodeList} selectedItems - List of selected navigation items
   */
  const initializeSelectedItem = (selectedItems) => {
    const firstSelected = selectedItems[0];
    firstSelected?.classList.add(ACTIVE_CLASS);
  };

  /**
   * Initializes inner menu toggle functionality
   */
  const init = () => {
    try {
      // Get all navigation elements
      const selectedItems = document.querySelectorAll(SELECTORS.selectedItems);
      const selectedLinks = document.querySelectorAll(SELECTORS.selectedLinks);
      const notSelectedItems = document.querySelectorAll(SELECTORS.notSelectedItems);
      const notSelectedLinks = document.querySelectorAll(SELECTORS.notSelectedLinks);

      // Early return if no elements found
      if (!selectedItems.length && !notSelectedItems.length) {
        console.warn('Inner menu: No navigation items found');
        return;
      }

      // Initialize first selected item as active
      initializeSelectedItem(selectedItems);

      // Set up click handlers for both selected and non-selected items
      setupClickHandlers(selectedLinks, selectedItems);
      setupClickHandlers(notSelectedLinks, notSelectedItems);
      
    } catch (error) {
      console.error('Inner menu initialization failed:', error);
    }
  };

  return { init };
})();

/**
 * Input optimization module
 * Removes size attributes from text inputs for better responsive behavior
 */
const InputOptimizationModule = (() => {
  /**
   * Removes size attribute from all text input elements
   * This allows inputs to be more responsive and follow CSS sizing
   */
  const removeSizeFromInputs = () => {
    try {
      const textInputs = document.querySelectorAll('input[type="text"]');
      
      textInputs.forEach(input => {
        if (input.hasAttribute('size')) {
          input.removeAttribute('size');
        }
      });
      
      console.debug(`Removed size attribute from ${textInputs.length} text inputs`);
    } catch (error) {
      console.error('Failed to remove size attributes from inputs:', error);
    }
  };

  return { init: removeSizeFromInputs };
})(); 

/**
 * Viewport meta tag module
 * Adds responsive viewport meta tag if not already present
 */
const ViewportModule = (() => {
  /**
   * Adds viewport meta tag for responsive design
   * Only adds if not already present to avoid duplicates
   */
  const addViewportMetaTag = () => {
    try {
      // Check if viewport meta tag already exists
      const existingViewport = document.querySelector('meta[name="viewport"]');
      
      if (existingViewport) {
        console.debug('Viewport meta tag already exists');
        return;
      }

      // Create and configure viewport meta tag
      const metaViewport = document.createElement('meta');
      metaViewport.name = 'viewport';
      metaViewport.content = 'width=device-width, initial-scale=1';
      
      // Add to document head
      const head = document.head || document.getElementsByTagName('head')[0];
      if (head) {
        head.appendChild(metaViewport);
        console.debug('Viewport meta tag added successfully');
      } else {
        console.warn('Document head not found, cannot add viewport meta tag');
      }
    } catch (error) {
      console.error('Failed to add viewport meta tag:', error);
    }
  };

  return { init: addViewportMetaTag };
})();

/**
 * Logo clickability module
 * Makes the navbar logo clickable, linking to the browsing page
 */
const LogoModule = (() => {
  let logoWrapper = null;
  let navbarElement = null;

  /**
   * Creates the clickable logo wrapper element
   * @param {string} href - URL to link to
   * @returns {HTMLElement} Logo wrapper element
   */
  const createLogoWrapper = (href) => {
    const wrapper = document.createElement('a');
    
    Object.assign(wrapper, {
      className: 'logo-link',
      href,
      title: 'Browse Crypta'
    });
    
    return wrapper;
  };

  /**
   * Finds the browsing menu link URL
   * @returns {string} Browsing page URL or fallback
   */
  const getBrowsingUrl = () => {
    const browsingLink = document.querySelector('#navlist li a[href]');
    return browsingLink?.href || '/';
  };

  /**
   * Initializes clickable logo functionality
   */
  const init = () => {
    try {
      navbarElement = document.getElementById('navbar');
      
      if (!navbarElement) {
        console.warn('Logo module: Navbar element not found');
        return;
      }

      const browsingUrl = getBrowsingUrl();
      logoWrapper = createLogoWrapper(browsingUrl);
      
      // Insert logo as first child of navbar
      navbarElement.insertBefore(logoWrapper, navbarElement.firstChild);
      
      console.debug('Logo clickability initialized successfully');
    } catch (error) {
      console.error('Failed to initialize logo clickability:', error);
    }
  };

  /**
   * Cleanup function for removing event listeners
   */
  const destroy = () => {
    logoWrapper?.remove();
    logoWrapper = null;
    navbarElement = null;
  };

  return { init, destroy };
})();

/**
 * Bookmarks clickability module
 * Makes entire bookmark table rows clickable for better UX
 */
const BookmarksModule = (() => {
  // Elements that should not trigger row clicks
  const EXCLUDED_TAGS = new Set(['INPUT', 'BUTTON', 'A']);
  const EXCLUDED_SELECTORS = ['form', 'a'];

  /**
   * Checks if click target should be excluded from row click handling
   * @param {EventTarget} target - Click event target
   * @returns {boolean} True if click should be ignored
   */
  const shouldExcludeClick = (target) => {
    if (EXCLUDED_TAGS.has(target.tagName)) {
      return true;
    }
    
    return EXCLUDED_SELECTORS.some(selector => target.closest(selector));
  };

  /**
   * Creates click handler for bookmark rows
   * @param {string} bookmarkUrl - URL to navigate to
   * @returns {Function} Click event handler
   */
  const createRowClickHandler = (bookmarkUrl) => (event) => {
    if (shouldExcludeClick(event.target)) {
      return;
    }
    
    try {
      window.location.href = bookmarkUrl;
    } catch (error) {
      console.error('Failed to navigate to bookmark:', error);
    }
  };

  /**
   * Sets up clickable functionality for a bookmark row
   * @param {HTMLElement} row - Table row element
   * @param {string} bookmarkUrl - URL to navigate to
   */
  const setupClickableRow = (row, bookmarkUrl) => {
    // Set visual indication of clickability
    row.style.cursor = 'pointer';
    
    // Add event listeners
    row.addEventListener('click', createRowClickHandler(bookmarkUrl));
  };

  /**
   * Processes all bookmark tables and makes rows clickable
   */
  const processBookmarkTables = () => {
    const bookmarkTables = document.querySelectorAll('#bookmarks table');
    let processedRows = 0;
    
    bookmarkTables.forEach(table => {
      const rows = table.querySelectorAll('tr');
      
      rows.forEach(row => {
        // Find bookmark title link in current row
        const titleLink = row.querySelector('a.bookmark-title, a.bookmark-title-updated');
        
        if (titleLink?.href) {
          setupClickableRow(row, titleLink.href);
          processedRows++;
        }
      });
    });
    
    console.debug(`Made ${processedRows} bookmark rows clickable`);
  };

  /**
   * Initializes bookmark clickability functionality
   */
  const init = () => {
    try {
      processBookmarkTables();
    } catch (error) {
      console.error('Failed to initialize bookmark clickability:', error);
    }
  };

  return { init };
})();

/**
 * Activelink image handling module
 * Shows placeholder while loading, then displays image or keeps placeholder if failed
 */
const ActivelinkModule = (() => {
  const PROCESSED_ATTRIBUTE = 'data-activelink-processed';
  const PLACEHOLDER_CLASS = 'activelink-placeholder';
  const LOADING_CLASS = 'activelink-loading';
  const DOCUMENT_ICON = '📄';
  const LOADING_ICON = '⏳';
  
  // Default dimensions and styling
  const DEFAULT_DIMENSIONS = { width: '108px', height: '36px' };
  const DEFAULT_MARGIN = '0 0 12px 0';
  
  const PLACEHOLDER_STYLES = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'var(--bg-tertiary, #2a2a2a)',
    border: '1px solid var(--border-color, #3a3a3a)',
    borderRadius: '4px',
    fontSize: '10px',
    color: 'var(--text-muted, #808080)',
    fontFamily: 'inherit',
    textAlign: 'center',
    opacity: '0.6',
    cursor: 'pointer',
    transition: 'opacity 0.2s ease'
  };

  /**
   * Extracts dimensions from image element
   * @param {HTMLImageElement} img - Image element
   * @returns {Object} Width and height values
   */
  const extractDimensions = (img) => ({
    width: img.style.width || DEFAULT_DIMENSIONS.width,
    height: img.style.height || DEFAULT_DIMENSIONS.height,
    margin: img.style.margin || DEFAULT_MARGIN
  });

  /**
   * Creates a styled placeholder element
   * @param {HTMLImageElement} img - Original image element
   * @param {boolean} isLoading - Whether this is a loading placeholder
   * @returns {HTMLElement} Placeholder element
   */
  const createPlaceholderElement = (img, isLoading = false) => {
    const placeholder = document.createElement('div');
    const dimensions = extractDimensions(img);
    
    placeholder.className = isLoading ? LOADING_CLASS : PLACEHOLDER_CLASS;
    placeholder.innerHTML = isLoading ? LOADING_ICON : DOCUMENT_ICON;
    
    // Copy title attribute for tooltip
    if (img.title) {
      placeholder.title = img.title;
    }
    
    // Apply styles
    Object.assign(placeholder.style, {
      ...PLACEHOLDER_STYLES,
      width: dimensions.width,
      height: dimensions.height,
      margin: dimensions.margin
    });
    
    // Add loading animation for loading placeholders
    if (isLoading) {
      placeholder.style.animation = 'pulse 1.5s ease-in-out infinite';
    }
    
    return placeholder;
  };

  /**
   * Sets up click handling for placeholder if parent is a link
   * @param {HTMLElement} placeholder - Placeholder element
   * @param {HTMLElement} parentLink - Parent link element
   */
  const setupPlaceholderInteractivity = (placeholder, parentLink) => {
    if (!parentLink) return;
    
    // Click handler
    placeholder.addEventListener('click', () => {
      try {
        parentLink.click();
      } catch (error) {
        console.error('Failed to trigger parent link click:', error);
      }
    });
    
    // Hover effects
    placeholder.addEventListener('mouseenter', () => {
      placeholder.style.opacity = '0.8';
    });
    
    placeholder.addEventListener('mouseleave', () => {
      placeholder.style.opacity = '0.6';
    });
  };

  /**
   * Replaces placeholder with loaded image
   * @param {HTMLElement} placeholder - Placeholder to replace
   * @param {HTMLImageElement} img - Loaded image element
   */
  const replaceWithImage = (placeholder, img) => {
    try {
      // Fade in the image
      img.style.opacity = '0';
      img.style.transition = 'opacity 0.3s ease';
      
      placeholder.parentNode?.replaceChild(img, placeholder);
      
      // Fade in animation
      requestAnimationFrame(() => {
        img.style.opacity = '1';
      });
    } catch (error) {
      console.error('Failed to replace placeholder with image:', error);
    }
  };

  /**
   * Creates and shows a loading placeholder, then loads the image
   * @param {HTMLImageElement} img - Image to process
   */
  const createLoadingPlaceholder = (img) => {
    try {
      // Create loading placeholder
      const placeholder = createPlaceholderElement(img, true);
      const parentLink = img.closest('a');
      
      setupPlaceholderInteractivity(placeholder, parentLink);
      
      // Store original image data
      const originalSrc = img.src;
      const originalAlt = img.alt;
      const originalTitle = img.title;
      
      // Replace image with loading placeholder immediately
      img.parentNode?.replaceChild(placeholder, img);
      
      // Create a new image element to load in background
      const newImg = new Image();
      newImg.src = originalSrc;
      newImg.alt = originalAlt;
      newImg.title = originalTitle;
      
      // Copy styles from original image
      newImg.style.width = extractDimensions({ style: img.style }).width;
      newImg.style.height = extractDimensions({ style: img.style }).height;
      newImg.style.margin = extractDimensions({ style: img.style }).margin;
      
      // Set up load/error handlers
      newImg.addEventListener('load', () => {
        // Image loaded successfully, replace placeholder with image
        replaceWithImage(placeholder, newImg);
      }, { once: true });
      
      newImg.addEventListener('error', () => {
        // Image failed to load, convert loading placeholder to error placeholder
        placeholder.className = PLACEHOLDER_CLASS;
        placeholder.innerHTML = DOCUMENT_ICON;
        placeholder.style.animation = 'none';
      }, { once: true });
      
    } catch (error) {
      console.error('Failed to create loading placeholder:', error);
    }
  };

  /**
   * Replaces image with error placeholder
   * @param {HTMLImageElement} img - Image to replace
   */
  const replaceWithErrorPlaceholder = (img) => {
    try {
      const placeholder = createPlaceholderElement(img, false);
      const parentLink = img.closest('a');
      
      setupPlaceholderInteractivity(placeholder, parentLink);
      
      // Replace the image
      img.parentNode?.replaceChild(placeholder, img);
    } catch (error) {
      console.error('Failed to create error placeholder for activelink image:', error);
    }
  };

  /**
   * Checks if image has loaded successfully
   * @param {HTMLImageElement} img - Image element
   * @returns {boolean} True if image loaded successfully
   */
  const hasImageLoaded = (img) => img.complete && img.naturalWidth > 0;

  /**
   * Checks if image has failed to load
   * @param {HTMLImageElement} img - Image element
   * @returns {boolean} True if image failed to load
   */
  const hasImageFailed = (img) => img.complete && img.naturalWidth === 0;

  /**
   * Processes a single activelink image
   * @param {HTMLImageElement} img - Image to process
   */
  const processImage = (img) => {
    // Skip if already processed
    if (img.hasAttribute(PROCESSED_ATTRIBUTE)) {
      return;
    }
    
    // Mark as processed
    img.setAttribute(PROCESSED_ATTRIBUTE, 'true');
    
    // Handle already loaded images
    if (hasImageLoaded(img)) {
      return; // Image already loaded successfully, no action needed
    }
    
    // Handle images that have already failed
    if (hasImageFailed(img)) {
      replaceWithErrorPlaceholder(img);
      return;
    }
    
    // For images that are still loading or haven't started loading,
    // always show a loading placeholder first
    createLoadingPlaceholder(img);
  };

  /**
   * Initializes activelink image handling
   */
  const init = () => {
    try {
      const activelinkImages = document.querySelectorAll('img[alt*="activelink"]');
      
      activelinkImages.forEach(processImage);
      
      console.debug(`Processed ${activelinkImages.length} activelink images`);
    } catch (error) {
      console.error('Failed to initialize activelink image handling:', error);
    }
  };

  return { init };
})();

/**
 * Theme switcher module
 * Handles light/dark theme switching functionality
 */
const ThemeSwitcherModule = (() => {
  let themeSwitcherButton = null;
  let navbarElement = null;
  
  // Theme states: 'light', 'dark'
  const THEME_STATES = ['light', 'dark'];
  const STORAGE_KEY = 'winterfacey-theme';
  const DEFAULT_THEME = 'light';

  /**
   * Gets current theme from localStorage or default
   * @returns {string} Current theme state
   */
  const getCurrentTheme = () => {
    try {
      return localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
    } catch (error) {
      console.warn('Failed to read theme from localStorage:', error);
      return DEFAULT_THEME;
    }
  };

  /**
   * Saves theme to localStorage
   * @param {string} theme - Theme to save
   */
  const saveTheme = (theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (error) {
      console.warn('Failed to save theme to localStorage:', error);
    }
  };

  /**
   * Toggles between light and dark themes
   * @param {string} currentTheme - Current theme state
   * @returns {string} Next theme state
   */
  const getNextTheme = (currentTheme) => {
    return currentTheme === 'light' ? 'dark' : 'light';
  };

  /**
   * Updates the button's data attribute for CSS styling
   * @param {string} theme - Current theme state
   */
  const updateButtonState = (theme) => {
    if (themeSwitcherButton) {
      themeSwitcherButton.setAttribute('data-theme', theme);
    }
  };

  /**
   * Applies the theme by updating CSS custom properties or media query preferences
   * Note: This is just for button state - actual theming is handled by CSS
   * @param {string} theme - Theme to apply
   */
  const applyTheme = (theme) => {
    // For now, we just update the button state
    // The actual theme switching logic will be implemented later
    updateButtonState(theme);
    console.debug(`Theme switcher: Set to ${theme} mode`);
  };

  /**
   * Handles theme switch button click
   */
  const handleThemeSwitch = () => {
    const currentTheme = getCurrentTheme();
    const nextTheme = getNextTheme(currentTheme);
    
    saveTheme(nextTheme);
    applyTheme(nextTheme);
  };

  /**
   * Creates the theme switcher button element
   * @returns {HTMLElement} Theme switcher button
   */
  const createThemeSwitcherButton = () => {
    const button = document.createElement('button');
    
    button.className = 'theme-toggle';
    button.setAttribute('data-theme', getCurrentTheme());
    button.setAttribute('aria-label', 'Toggle theme');
    button.setAttribute('title', 'Toggle between light and dark themes');
    
    // Create icon container
    const iconSpan = document.createElement('span');
    iconSpan.className = 'theme-toggle-icon';
    button.appendChild(iconSpan);
    
    // Add click handler
    button.addEventListener('click', handleThemeSwitch);
    
    return button;
  };


  /**
   * Initializes the theme switcher functionality
   */
  const init = () => {
    try {
      navbarElement = document.getElementById('navbar');
      const navlistElement = document.getElementById('navlist');
      
      if (!navbarElement || !navlistElement) {
        console.warn('Theme switcher: Required navigation elements not found');
        return;
      }

      // Create the theme switcher button
      themeSwitcherButton = createThemeSwitcherButton();
      
      // Position it right after the navlist
      if (navlistElement.nextSibling) {
        navbarElement.insertBefore(themeSwitcherButton, navlistElement.nextSibling);
      } else {
        navbarElement.appendChild(themeSwitcherButton);
      }
      
      // Apply current theme
      const currentTheme = getCurrentTheme();
      applyTheme(currentTheme);
      
      console.debug('Theme switcher initialized successfully');
    } catch (error) {
      console.error('Failed to initialize theme switcher:', error);
    }
  };

  /**
   * Cleanup function for removing event listeners and elements
   */
  const destroy = () => {
    themeSwitcherButton?.remove();
    themeSwitcherButton = null;
    navbarElement = null;
  };

  return { init, destroy };
})();

/**
 * Main application initialization
 * Coordinates all modules and handles DOM ready state
 */
(() => {
  'use strict';

  // Module initialization order (important for dependencies)
  const modules = [
    { name: 'Viewport', module: ViewportModule },
    { name: 'Input Optimization', module: InputOptimizationModule },
    { name: 'Mobile Menu', module: MobileMenuModule },
    { name: 'Inner Menu', module: InnerMenuModule },
    { name: 'Logo', module: LogoModule },
    { name: 'Bookmarks', module: BookmarksModule },
    { name: 'Activelink', module: ActivelinkModule },
    { name: 'Theme Switcher', module: ThemeSwitcherModule }
  ];

  /**
   * Initializes all application modules
   */
  const initializeModules = () => {
    console.debug('Initializing WinterFacey theme modules...');
    
    modules.forEach(({ name, module }) => {
      try {
        module.init();
        console.debug(`✓ ${name} module initialized`);
      } catch (error) {
        console.error(`✗ Failed to initialize ${name} module:`, error);
      }
    });
    
    console.debug('WinterFacey theme initialization complete');
  };

  /**
   * Handles cleanup on page unload (for modules that need it)
   */
  const handlePageUnload = () => {
    modules.forEach(({ name, module }) => {
      try {
        module.destroy?.();
      } catch (error) {
        console.error(`Failed to cleanup ${name} module:`, error);
      }
    });
  };

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeModules, { once: true });
  } else {
    // DOM is already loaded
    initializeModules();
  }

  // Cleanup on page unload
  window.addEventListener('beforeunload', handlePageUnload, { once: true });
})();


