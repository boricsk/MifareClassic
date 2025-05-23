<p align="center">
  <img src=https://devnullsec.hu/logo_small.svg height="64" width="64">
</p>

## MIFARE Classic 4K NFC Card handling 
### C# library for handling above NFC cards


- Usage
> With this class it is possible to write to MIFARE Classic 4k cards with the default authentication key, retrieve the reader name and the card UID. For writing, the input is given in string format, the read is also given as string type. If the size of the string given as input is larger than the card memory the input will be truncated. Let see the examples.

```csharp
namespace MifareClassic4KDemo
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //Create class instance
            MifareClassicCard myCard = new MifareClassicCard();
            //Get reader name
            Console.WriteLine(myCard.GetReaderName());
            //Get card UID
            Console.WriteLine(myCard.GetCardUID());
            
            //Write data
            string input = "Vestibulum mattis consequat purus, molestie bibendum est commodo interdum. Vestibulum eu dolor lectus. Morbi malesuada sem eget rutrum venenatis. Etiam non lorem neque. Pellentesque tellus erat, convallis id mattis non, pretium sit amet leo.";
            myCard.M4kWriteAllBlocksToString(input, true);
            
            //Read data
            Console.WriteLine(myCard.M4kReadAllBlocksToString());

            //Close context
            myCard.CardDisconnect();

        }
    }
}
```
<p align="center">
  <img src=./out.jpg>
</p>

