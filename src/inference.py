# author: Neev Modi

from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch
import warnings

warnings.filterwarnings("ignore", message=".*Tried to instantiate class '__path__._path'.*")

class InferenceEngine:
    def __init__(self, model_name="Salesforce/codet5-base-multi-sum"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = self.model.to(self.device)

    def generate_summary(self, prompt: str, max_length=128):
        """
        Generates a summary from the enriched prompt.
        """
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512).to(self.device)

        with torch.no_grad():
            full_summary_ids = self.model.generate(
                inputs["input_ids"],
                max_length=max_length,
                min_length=10,
                num_beams=4,
                early_stopping=True
            )

        summary = self.tokenizer.decode(full_summary_ids[0], skip_special_tokens=True)
        return summary
