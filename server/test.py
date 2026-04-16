from requests import post


response = post('http://localhost:8787/api/v1/ai', json={'link': 'https://vk.com/some-data'})
print(response, response.content)