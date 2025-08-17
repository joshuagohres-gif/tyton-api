const validator = require('validator');

class InputValidator {
  constructor() {
    // Common patterns
    this.patterns = {
      handle: /^[a-zA-Z0-9_-]{2,30}$/,
      name: /^[a-zA-Z\s'-]{1,100}$/,
      tags: /^[a-zA-Z0-9,\s-]{0,200}$/,
      title: /^.{1,200}$/,
      description: /^.{0,2000}$/,
      category: /^[a-zA-Z\s-]{1,50}$/
    };
  }

  // Email validation
  validateEmail(email) {
    if (!email || typeof email !== 'string') {
      return { valid: false, error: 'Email is required' };
    }
    
    if (!validator.isEmail(email)) {
      return { valid: false, error: 'Invalid email format' };
    }
    
    if (email.length > 254) {
      return { valid: false, error: 'Email too long' };
    }
    
    return { valid: true, sanitized: email.toLowerCase().trim() };
  }

  // Password validation
  validatePassword(password) {
    if (!password || typeof password !== 'string') {
      return { valid: false, error: 'Password is required' };
    }
    
    if (password.length < 6) {
      return { valid: false, error: 'Password must be at least 6 characters' };
    }
    
    if (password.length > 128) {
      return { valid: false, error: 'Password too long' };
    }
    
    // Check for common weak passwords
    const weakPasswords = ['password', '123456', 'password123', 'admin', 'qwerty'];
    if (weakPasswords.includes(password.toLowerCase())) {
      return { valid: false, error: 'Password is too common' };
    }
    
    return { valid: true, sanitized: password };
  }

  // Name validation
  validateName(name) {
    if (!name || typeof name !== 'string') {
      return { valid: false, error: 'Name is required' };
    }
    
    const sanitized = name.trim();
    if (!this.patterns.name.test(sanitized)) {
      return { valid: false, error: 'Name contains invalid characters or is too long' };
    }
    
    return { valid: true, sanitized };
  }

  // Handle validation (@username)
  validateHandle(handle) {
    if (!handle || typeof handle !== 'string') {
      return { valid: false, error: 'Handle is required' };
    }
    
    let sanitized = handle.trim();
    if (sanitized.startsWith('@')) {
      sanitized = sanitized.substring(1);
    }
    
    if (!this.patterns.handle.test(sanitized)) {
      return { valid: false, error: 'Handle must be 2-30 characters, alphanumeric, underscore, or dash only' };
    }
    
    return { valid: true, sanitized: '@' + sanitized };
  }

  // Title validation
  validateTitle(title) {
    if (!title || typeof title !== 'string') {
      return { valid: false, error: 'Title is required' };
    }
    
    const sanitized = title.trim();
    if (!this.patterns.title.test(sanitized)) {
      return { valid: false, error: 'Title is too long (max 200 characters)' };
    }
    
    if (sanitized.length === 0) {
      return { valid: false, error: 'Title cannot be empty' };
    }
    
    return { valid: true, sanitized };
  }

  // Description validation
  validateDescription(description) {
    if (description && typeof description !== 'string') {
      return { valid: false, error: 'Description must be text' };
    }
    
    const sanitized = description ? description.trim() : '';
    if (!this.patterns.description.test(sanitized)) {
      return { valid: false, error: 'Description is too long (max 2000 characters)' };
    }
    
    return { valid: true, sanitized };
  }

  // Tags validation
  validateTags(tags) {
    if (tags && typeof tags !== 'string') {
      return { valid: false, error: 'Tags must be text' };
    }
    
    const sanitized = tags ? tags.trim() : '';
    if (!this.patterns.tags.test(sanitized)) {
      return { valid: false, error: 'Tags contain invalid characters or are too long' };
    }
    
    // Validate individual tags
    if (sanitized) {
      const tagList = sanitized.split(',').map(tag => tag.trim());
      if (tagList.length > 10) {
        return { valid: false, error: 'Too many tags (max 10)' };
      }
      
      for (const tag of tagList) {
        if (tag.length > 30) {
          return { valid: false, error: 'Individual tags must be 30 characters or less' };
        }
      }
    }
    
    return { valid: true, sanitized };
  }

  // Category validation
  validateCategory(category) {
    if (!category || typeof category !== 'string') {
      return { valid: false, error: 'Category is required' };
    }
    
    const sanitized = category.trim();
    if (!this.patterns.category.test(sanitized)) {
      return { valid: false, error: 'Category contains invalid characters or is too long' };
    }
    
    return { valid: true, sanitized };
  }

  // Location validation
  validateLocation(location) {
    if (location && typeof location !== 'string') {
      return { valid: false, error: 'Location must be text' };
    }
    
    const sanitized = location ? location.trim() : '';
    if (sanitized.length > 100) {
      return { valid: false, error: 'Location is too long (max 100 characters)' };
    }
    
    return { valid: true, sanitized };
  }

  // URL validation
  validateUrl(url) {
    if (url && typeof url !== 'string') {
      return { valid: false, error: 'URL must be text' };
    }
    
    if (!url) {
      return { valid: true, sanitized: '' };
    }
    
    const sanitized = url.trim();
    if (!validator.isURL(sanitized, { protocols: ['http', 'https'] })) {
      return { valid: false, error: 'Invalid URL format' };
    }
    
    return { valid: true, sanitized };
  }

  // ID validation
  validateId(id) {
    if (!id || typeof id !== 'string') {
      return { valid: false, error: 'ID is required' };
    }
    
    // Check for UUID format or our custom format
    if (!validator.isUUID(id.replace(/^(user_|item_|discussion_|paper_)/, ''))) {
      return { valid: false, error: 'Invalid ID format' };
    }
    
    return { valid: true, sanitized: id };
  }

  // Sanitize HTML content (strip all HTML tags)
  sanitizeHtml(content) {
    if (!content || typeof content !== 'string') {
      return '';
    }
    
    return content
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/&lt;/g, '<')   // Decode common entities
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#039;/g, "'")
      .trim();
  }

  // Validate user registration data
  validateUserRegistration(data) {
    const errors = [];
    const sanitized = {};

    const emailResult = this.validateEmail(data.email);
    if (!emailResult.valid) errors.push(emailResult.error);
    else sanitized.email = emailResult.sanitized;

    const passwordResult = this.validatePassword(data.password);
    if (!passwordResult.valid) errors.push(passwordResult.error);
    else sanitized.password = passwordResult.sanitized;

    const nameResult = this.validateName(data.name);
    if (!nameResult.valid) errors.push(nameResult.error);
    else sanitized.name = nameResult.sanitized;

    if (data.handle) {
      const handleResult = this.validateHandle(data.handle);
      if (!handleResult.valid) errors.push(handleResult.error);
      else sanitized.handle = handleResult.sanitized;
    }

    return { valid: errors.length === 0, errors, sanitized };
  }

  // Validate item (project/equipment) data
  validateItemData(data) {
    const errors = [];
    const sanitized = {};

    const titleResult = this.validateTitle(data.title);
    if (!titleResult.valid) errors.push(titleResult.error);
    else sanitized.title = titleResult.sanitized;

    const descResult = this.validateDescription(data.description);
    if (!descResult.valid) errors.push(descResult.error);
    else sanitized.description = descResult.sanitized;

    const tagsResult = this.validateTags(data.tags);
    if (!tagsResult.valid) errors.push(tagsResult.error);
    else sanitized.tags = tagsResult.sanitized;

    const locationResult = this.validateLocation(data.location);
    if (!locationResult.valid) errors.push(locationResult.error);
    else sanitized.location = locationResult.sanitized;

    // Validate type
    if (!['project', 'equipment'].includes(data.type)) {
      errors.push('Invalid item type');
    } else {
      sanitized.type = data.type;
    }

    return { valid: errors.length === 0, errors, sanitized };
  }

  // Validate journal paper data
  validateJournalPaper(data) {
    const errors = [];
    const sanitized = {};

    const titleResult = this.validateTitle(data.title);
    if (!titleResult.valid) errors.push(titleResult.error);
    else sanitized.title = titleResult.sanitized;

    // Validate abstract (longer description)
    if (!data.abstract || typeof data.abstract !== 'string') {
      errors.push('Abstract is required');
    } else {
      const abstractSanitized = data.abstract.trim();
      if (abstractSanitized.length === 0) {
        errors.push('Abstract cannot be empty');
      } else if (abstractSanitized.length > 5000) {
        errors.push('Abstract is too long (max 5000 characters)');
      } else {
        sanitized.abstract = abstractSanitized;
      }
    }

    // Validate authors
    if (!data.authors) {
      errors.push('Authors are required');
    } else if (Array.isArray(data.authors)) {
      const validAuthors = data.authors.filter(author => typeof author === 'string' && author.trim());
      if (validAuthors.length === 0) {
        errors.push('At least one valid author is required');
      } else {
        sanitized.authors = validAuthors.map(author => author.trim());
      }
    } else if (typeof data.authors === 'string') {
      const authorTrimmed = data.authors.trim();
      if (authorTrimmed.length === 0) {
        errors.push('Authors cannot be empty');
      } else {
        sanitized.authors = [authorTrimmed];
      }
    } else {
      errors.push('Authors must be a string or array');
    }

    const categoryResult = this.validateCategory(data.category);
    if (!categoryResult.valid) errors.push(categoryResult.error);
    else sanitized.category = categoryResult.sanitized;

    // Validate status
    const validStatuses = ['draft', 'submitted', 'peer-review', 'published', 'rejected'];
    if (data.status && !validStatuses.includes(data.status)) {
      errors.push('Invalid status');
    } else {
      sanitized.status = data.status || 'draft';
    }

    // Validate keywords
    if (data.keywords) {
      if (Array.isArray(data.keywords)) {
        const validKeywords = data.keywords.filter(kw => typeof kw === 'string' && kw.trim());
        sanitized.keywords = validKeywords.map(kw => kw.trim());
      } else if (typeof data.keywords === 'string') {
        sanitized.keywords = data.keywords.split(',').map(kw => kw.trim()).filter(kw => kw);
      } else {
        errors.push('Keywords must be an array or comma-separated string');
      }
    } else {
      sanitized.keywords = [];
    }

    // Validate file URL
    if (data.fileUrl) {
      const urlResult = this.validateUrl(data.fileUrl);
      if (!urlResult.valid) errors.push(urlResult.error);
      else sanitized.fileUrl = urlResult.sanitized;
    } else {
      sanitized.fileUrl = null;
    }

    return { valid: errors.length === 0, errors, sanitized };
  }
}

module.exports = InputValidator;