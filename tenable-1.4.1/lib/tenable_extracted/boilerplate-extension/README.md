# Dynatrace Extension Boilerplate README

#

# This boilerplate provides a complete foundation for building Dynatrace extensions

# that integrate with external APIs and map data to Dynatrace semantic dictionary.

## 📁 Project Structure

```
boilerplate-extension/
├── __main__.py              # Main extension entry point
├── rest_interface.py         # HTTP client & authentication
├── config_template.json     # Configuration template
├── models/
│   └── __init__.py         # Data models for external API
└── utils/
    ├── shared.py           # Common utilities
    └── data_processing.py # Business logic & transformations
```

## 🚀 Getting Started

### 1. Replace TODO Comments

The boilerplate contains extensive TODO comments indicating what needs to be customized:

- **API Integration**: Replace external API connection details
- **Data Models**: Update models to match your API's data structures
- **Data Processing**: Implement your specific business logic
- **Semantic Mapping**: Map your data to Dynatrace semantic dictionary
- **Configuration**: Update configuration structure for your needs

### 2. Key Files to Customize

#### `__main__.py`

- Replace API client initialization
- Update data collection methods
- Configure scheduling and frequency
- Implement your specific data processing logic

#### `models/__init__.py`

- Replace with your API's data structures
- Add nested objects and relationships
- Implement proper field mappings

#### `utils/data_processing.py`

- Implement your data transformation logic
- Map to Dynatrace semantic dictionary
- Add validation and enrichment logic

#### `rest_interface.py`

- Update authentication methods if needed
- Add API-specific error handling
- Configure retry logic and timeouts

### 3. Configuration Setup

Update `config_template.json` with your specific requirements:

```json
{
  "connection": {
    "externalApiUrl": "https://your-api.com",
    "apiKey": "your-api-key",
    "apiSecret": "your-api-secret"
  },
  "products": {
    "yourDataType": true
  },
  "advancedOptions": {
    "collectionFrequency": 1,
    "firstTimeFetchWindow": 24
  }
}
```

## 🎯 Dynatrace Semantic Dictionary Mapping

### Key Semantic Fields to Use

#### Security Events

```python
{
    "event.type": "SECURITY_EVENT",
    "event.kind": "SECURITY_FINDING",  # or "VULNERABILITY", "THREAT"
    "security.finding.id": "unique-id",
    "security.finding.name": "finding-name",
    "security.finding.severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "security.finding.status": "OPEN|CLOSED|RESOLVED"
}
```

#### Audit Events

```python
{
    "event.type": "AUDIT_EVENT",
    "event.kind": "AUDIT_LOG",
    "audit.identity": "user-name",
    "audit.action": "action-performed",
    "audit.result": "Succeeded|Failed",
    "audit.time": "2024-01-01T00:00:00Z"
}
```

#### Entity Mapping

```python
{
    "dt.entity.host": "hostname",
    "dt.entity.process_group": "service-name",
    "dt.entity.custom_device": "device-id"
}
```

#### Custom Fields

```python
{
    "custom.your_field": "value",
    "dt.custom.metric": 123.45
}
```

## 🔧 Implementation Steps

### Step 1: API Integration

1. Replace external API client initialization
2. Implement data fetching methods
3. Add authentication handling
4. Configure error handling and retries

### Step 2: Data Models

1. Create models matching your API structure
2. Add validation and normalization
3. Implement nested object handling
4. Add helper methods for data access

### Step 3: Data Processing

1. Implement transformation logic
2. Map to Dynatrace semantic dictionary
3. Add data enrichment and validation
4. Handle different data types

### Step 4: Configuration

1. Update configuration structure
2. Add validation for required fields
3. Implement default values
4. Add environment-specific settings

### Step 5: Testing & Deployment

1. Test with sample data
2. Validate semantic dictionary mapping
3. Test error handling scenarios
4. Deploy to Dynatrace environment

## 📚 Best Practices

### Data Processing

- Always validate data before processing
- Use proper error handling and logging
- Implement data chunking for large datasets
- Add retry logic for failed operations

### Semantic Dictionary

- Use standard Dynatrace semantic fields when possible
- Create meaningful custom field names
- Maintain consistent naming conventions
- Document your field mappings

### Performance

- Implement efficient data fetching
- Use pagination for large datasets
- Cache frequently accessed data
- Monitor memory usage and processing time

### Security

- Secure API credentials storage
- Use HTTPS for all API communications
- Implement proper authentication
- Log security-relevant events

## 🐛 Troubleshooting

### Common Issues

1. **Authentication Failures**: Check API credentials and endpoints
2. **Data Mapping Errors**: Validate semantic dictionary field names
3. **Performance Issues**: Implement proper chunking and pagination
4. **Memory Issues**: Monitor data processing and cleanup

### Debugging

- Enable debug logging in configuration
- Use extension logs for troubleshooting
- Validate data at each processing step
- Test with small datasets first

## 📖 Additional Resources

- [Dynatrace Extension SDK Documentation](https://www.dynatrace.com/support/help/extend-dynatrace/extensions20)
- [Dynatrace Semantic Dictionary](https://www.dynatrace.com/support/help/how-to-use-dynatrace/dynatrace-api/events-api/event-properties)
- [Dynatrace Events API](https://www.dynatrace.com/support/help/how-to-use-dynatrace/dynatrace-api/events-api)

## 🤝 Contributing

When extending this boilerplate:

1. Follow the existing code structure
2. Add comprehensive documentation
3. Include error handling
4. Test thoroughly before deployment
5. Update this README with new features
