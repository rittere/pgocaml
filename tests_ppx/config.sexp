( ( (And
      ( (Or
          ( (Rule (typnam userid))
            (Rule (typnam int4))
            (Rule (typnam int32))
          )
        )
        (Or
          ( (Rule (argnam userid))
            (Rule (colnam userid))
          )
        )
      )
    )
    ( (serialize Userid.to_string)
      (deserialize Userid.from_string)
    )
  )
  ( (And
      ( (Or
          ( (Rule (typnam cash_money))
            (Rule (typnam float))
          )
        )
        (Or
          ( (Rule (argnam salary))
            (Rule (colnam salary))
            (Rule (argnam customsalary))
          )
        )
      )
    )
    ( (serialize "fun x -> String.(sub x 1 (length x - 1)) |> String.trim")
      (deserialize "fun x -> \"$\" ^ x")
    )
  )
)