from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
app=FastAPI()

def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="postgres",
        user="postgres",
        password="luffy",
        port="5432"
    )

class ProductCreate(BaseModel):
    product_name: str
    units: str
    price: int

class ProductUpdate(BaseModel):
    product_name:str
    units:str
    price:int

class ProductPatch(BaseModel):
    units:str
    price:int

@app.get("/products")
def get_products():
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
        SELECT product_id,product_name,units,price
        FROM products
        """)
    rows=cursor.fetchall()
    print("ROWS:",rows)
    print("NUMBER OF ROWS:",len(rows))
    cursor.close()
    conn.close()
    products=[]
    for row in rows:
        products.append( {
            "product_id":row[0],
            "product_name":row[1],
            "units":row[2],
            "price":row[3]
        })
# IMPORTANT: return is outside the loop
    return{"products":products}      

@app.get("/products/{product_id}")
def get_products(product_id:int):
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
    SELECT product_name,units,price
    FROM products
    WHERE product_id=%s
    """,(product_id,))
    row=cursor.fetchone()
    cursor.close()
    conn.close()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="product not found"
        )
    return{
        "product_name":row[0],
        "units":row[1],
        "price":row[2]
    }

@app.post("/products")
def create_products(product: ProductCreate):
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
    INSERT INTO products (product_name,units,price)
    VALUES (%s,%s,%s)
    RETURNING product_name,units,price
    """, (
        product.product_name,
        product.units,
        product.price
    ))
    row=cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    return{
        "message": "Product created",
        "product":{
            "product_name":row[0],
            "units":row[1],
            "price":row[2]
        }
    }
@app.put("/products/{product_id}")
def update_products(
    product_id:int,
    product:ProductPatch
):
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
    UPDATE products
    SET product_name=%s,units=%s,price=%s
    WHERE product_id=%s
    RETURNING product_name,units,price
    """,(
        product.product_name,
        product.units,
        product.price,
        product_id
    ))
    row=cursor.fetchone()
    if row is None:
        cursor.close()
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Product not found"      
        )
    conn.commit()
    cursor.close()
    conn.close()

    return{
            "message":"Product completely updated",
            "product":{
                "product_name":row[0],
                "units":row[1],
                "price":row[2]
            }
        }


@app.patch("/products/{product_id}")
def patch_product (
    product_id:int,
    product: ProductPatch
):
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
    UPDATE products
    SET units=%s
    WHERE product_id=%s
    RETURNING product_name,units,price
    """,(
        product.units,
        product_id
    ))
    row=cursor.fetchone()
    if row is None:
        cursor.close()
        conn.close()
        raise HTTPException(
        status_code=404,
        detail="Product not found"
        )
    conn.commit()
    cursor.close()
    conn.close()
    return{
        "message":"Product partially updated",
        "product":{
            "product_name":row[0],
            "units":row[1],
            "price":row[2]
        }
    }    

@app.delete("/products/{product_id}")
def delete_product(product_id:int):
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""
    DELETE FROM products
    WHERE product_id=%s
    RETURNING product_name,units,price
    """,(product_id,))
    row=cursor.fetchone()
    if row is None:
        cursor.close()
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Product not found"
        )
    conn.commit()
    conn.close()
    return{
        "message":"product deleted",
        "product":{
            "product_name":row[0],
            "units":row[1],
            "price":row[2]   
                      }
    }



         