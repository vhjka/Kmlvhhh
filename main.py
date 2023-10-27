import requests
import json

# قم بتعيين مفتاح API الخاص بك
API_KEY = "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"


def get_response(prompt):
  """
  يحصل على استجابة من ChatGPT

  Args:
    prompt: النص لإنشاء استجابة له

  Returns:
    استجابة ChatGPT
  """

  # تحقق من صحة المفتاح API
  if not API_KEY:
    raise ValueError("لم يتم تعيين مفتاح API.")

  # قم بإنشاء طلب إلى ChatGPT
  url = "https://api.openai.com/v1/engines/davinci/completions"
  headers = {"Authorization": f"Bearer {API_KEY}"}
  data = {
    "prompt": prompt,
    "temperature": 0.7,
    "max_tokens": 100,
    "top_p": 0.9,
  }
  response = requests.post(url, headers=headers, json=data)

  # فك تشفير استجابة ChatGPT
  try:
    response_json = json.loads(response.text)
    response_text = response_json["choices"][0]["text"]
  except json.JSONDecodeError:
    raise ValueError(
        f"حدث خطأ في استجابة API: {response.text}"
    )
  except KeyError:
    raise ValueError(
        "لم يتم العثور على مفتاح `choices` في استجابة API."
    )

  return response_text


def main():
  # احصل على نص المستخدم
  prompt = input("اكتب نصًا لإنشاء استجابة له: ")

  # احصل على استجابة من ChatGPT
  response = get_response(prompt)

  # اطبع الاستجابة
  print(response)


if __name__ == "__main__":
  main()
	
